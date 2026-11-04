# TOTP Implementation: RFC 6238 Multi-Factor Authentication Engine

## 1. Overview

Time-Based One-Time Passwords (TOTP) provide a cryptographically sound, out-of-band second factor for user authentication. By deriving a temporary 6-digit numeric token from a shared secret and the current UNIX timestamp, TOTP protects accounts even if the user's primary password is leaked through credential stuffing or phishing.

This document details the standalone RFC 6238 TOTP engine implemented in **SHIVAY Core** (`src/shivai/security/totp.py`), featuring **zero third-party dependencies**, **RFC 4226 Dynamic Truncation**, **clock drift tolerance**, and **standard QR provisioning**.

---

## 2. Mathematical Foundation & RFC 6238 Specification

TOTP is derived from HMAC-Based One-Time Passwords (HOTP, RFC 4226), replacing the event counter $C$ with a time-based counter $T$:

$$T = \left\lfloor \frac{\text{Current UNIX Time} - T_0}{X} \right\rfloor$$

- $T_0$: The epoch offset (default: $0$, corresponding to January 1, 1970 UTC).
- $X$: The time-step interval in seconds (default: $30$ seconds).

### Algorithm Steps:
1. **Derive Counter:** Calculate 64-bit integer $T = \lfloor \text{time}() / 30 \rfloor$ and pack into 8 big-endian bytes: `struct.pack(">Q", T)`.
2. **Compute HMAC-SHA1:** Generate 20-byte digest: $\text{MAC} = \text{HMAC-SHA1}(K, \text{packed\_T})$, where $K$ is the Base32-decoded shared secret.
3. **Dynamic Truncation:** Extract low-order 4 bits of the last byte to determine offset $O = \text{MAC}[19] \ \& \ \text{0x0F}$.
4. **Extract 31-bit Integer:** Read 4 bytes starting at offset $O$, masking the most significant bit:
   $$\text{Code}_{\text{int}} = (\text{MAC}[O \dots O+3] \ \& \ \text{0x7FFFFFFF})$$
5. **Compute 6-Digit Token:**
   $$\text{Token} = \text{Code}_{\text{int}} \pmod{10^6} \quad \text{(zero-padded to 6 digits)}$$

---

## 3. Clock Skew & Drift Tolerance Window

Network latency and client-server clock desynchronization can cause users to submit tokens generated in the previous interval or delayed into the next interval.

The implementation evaluates a configurable drift window ($\text{drift\_steps} = 1$, checking 3 intervals: $T-1, T, T+1$):

```
       Interval T-1                Interval T                Interval T+1
  [ 30s Previous Step ]      [ 30s Current Step ]        [ 30s Next Step ]
|──────────────────────────|──────────────────────────|──────────────────────────|
-30s                       0s                         +30s                      +60s
                           ▲
                   User Submits Code
   <──────────────── Total 90s Validation Window ────────────────>
```

---

## 4. Source Code Implementation

Verified implementation from `src/shivai/security/totp.py`:

```python
"""
SHIVAY Security: RFC 6238 TOTP (Time-Based One-Time Password) Engine.
Zero external dependencies (uses standard library base64, hashlib, hmac, struct, time).
"""

from __future__ import annotations
import base64
import hashlib
import hmac
import secrets
import struct
import time
from typing import Optional
from urllib.parse import quote

class TOTPEngine:
    """
    Standard RFC 6238 TOTP implementation.
    Generates and verifies 6-digit one-time passcodes with clock drift tolerance.
    """

    @staticmethod
    def generate_secret(num_bytes: int = 20) -> str:
        """
        Generate a cryptographically secure Base32-encoded random secret key.
        Default 20 bytes (160 bits) as recommended by RFC 6238.
        """
        random_bytes = secrets.token_bytes(num_bytes)
        return base64.b32encode(random_bytes).decode("utf-8").replace("=", "")

    @staticmethod
    def generate_code(secret_b32: str, interval: int = 30, for_time: Optional[float] = None) -> str:
        """Compute the 6-digit TOTP code for a given timestamp."""
        current_time = for_time if for_time is not None else time.time()
        clean_secret = secret_b32.strip().upper()
        padding = (8 - len(clean_secret) % 8) % 8
        clean_secret += "=" * padding

        key = base64.b32decode(clean_secret)
        counter = int(current_time // interval)
        counter_bytes = struct.pack(">Q", counter)

        # Compute HMAC-SHA1
        mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()

        # Dynamic truncation (RFC 4226 Section 5.4)
        offset = mac[-1] & 0x0F
        code_int = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
        return str(code_int % 1_000_000).zfill(6)

    @classmethod
    def verify_code(
        cls,
        secret_b32: str,
        code: str,
        interval: int = 30,
        drift_steps: int = 1,
        for_time: Optional[float] = None,
    ) -> bool:
        """
        Verify user-provided code with constant-time equality check.
        drift_steps allows clock skew tolerance (drift_steps=1 checks past, current, future).
        """
        if not code or len(code.strip()) != 6:
            return False

        clean_code = code.strip()
        current_time = for_time if for_time is not None else time.time()

        for step in range(-drift_steps, drift_steps + 1):
            eval_time = current_time + (step * interval)
            candidate = cls.generate_code(secret_b32, interval=interval, for_time=eval_time)
            if hmac.compare_digest(candidate, clean_code):
                return True

        return False

    @staticmethod
    def get_provisioning_uri(secret_b32: str, account_name: str, issuer_name: str = "SHIVAY") -> str:
        """Generate standard otpauth:// URI for authenticator QR code rendering."""
        clean_secret = secret_b32.strip().upper()
        account_quoted = quote(account_name)
        issuer_quoted = quote(issuer_name)
        return (
            f"otpauth://totp/{issuer_quoted}:{account_quoted}"
            f"?secret={clean_secret}&issuer={issuer_quoted}&algorithm=SHA1&digits=6&period=30"
        )
```

---

## 5. Verification & Testing Evidence

- **Status:** **`[TESTED]`**
- **Test File:** `tests/test_transferred_skills.py::TestTransferredSkills::test_totp_generation_and_verification`
- **Verification Assertions:**
  1. Secret generated has $\ge 16$ characters Base32 entropy.
  2. Generated code is exactly 6 digits numeric (`assert len(code) == 6 and code.isdigit()`).
  3. Correct codes verify as `True`.
  4. Incorrect codes verify as `False`.
  5. Past codes within $T - 30\text{s}$ verify as `True` under `drift_steps=1`.
  6. Provisioning URI format conforms to standard `otpauth://totp/SHIVAY:account?secret=...`.
- **Result:** PASSED in 0.04s.

---

## 6. Security Considerations & Limitations

1. **Replay Invalidation (Burn After Use):** A 6-digit TOTP code remains mathematically valid across the 30-second interval. To prevent an adversary from replaying an intercepted code within the same 30-second slice, the server must record the last verified time-step in cache and reject duplicate attempts for that step.
2. **SHA-1 in TOTP:** RFC 6238 specifies SHA-1 as the default for interoperability with authenticator apps (Google Authenticator, Microsoft Authenticator). While SHA-1 collision vulnerabilities exist, HMAC-SHA1 remains secure against pre-image and forgery attacks because the key is secret.

---

## 7. References

- RFC 6238: *TOTP: Time-Based One-Time Password Algorithm*.
- RFC 4226: *HOTP: An HMAC-Based One-Time Password Algorithm*.
- NIST SP 800-63B: *Authenticator and Credential Management Guidelines*.
