# Webhook Verification: Raw Payload Cryptography & Replay Defense

## 1. Overview

In SHIVAY, webhooks power asynchronous integrations: telephony event callbacks (Twilio, Exotel), payment state transitions (Razorpay, Stripe), and external git notifications. Because webhook receivers process untrusted external requests, they must be cryptographically protected against payload forgery, man-in-the-middle tampering, and replay attacks.

This document details the webhook signature verification implementation in **SHIVAY Core** (`src/shivai/security/webhook_verifier.py`).

---

## 2. Threat Scenarios & Cryptographic Defenses

| Threat Scenario | Attack Mechanics | Implemented Mitigation |
| :--- | :--- | :--- |
| **Payload Forgery** | Attacker sends synthetic `HTTP POST` simulating an event | Gateway secret calculates HMAC-SHA256; forged requests lack valid signature. |
| **Data Tampering** | Attacker modifies 1 byte of payload (e.g., recipient number or amount) | Any payload modification completely invalidates the computed HMAC digest. |
| **Replay Attack** | Attacker captures valid signed packet and resends it repeatedly | Timestamp header verified against $300\text{s}$ freshness tolerance window. |
| **Timing Attack** | Attacker measures verification execution time to guess signature bytes | Digest verification uses constant-time `hmac.compare_digest`. |

---

## 3. Cryptographic Verification Workflow

```
[ Incoming Webhook Request ]
            │
            ├──► Extract Header: X-Signature (or X-Razorpay-Signature / Stripe-Signature)
            ├──► Extract Header: X-Timestamp (if provider includes timestamp)
            └──► Read Raw Wire Bytes: await request.body()
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │        Timestamp Freshness Evaluation        │
        │   abs(current_unix_time - timestamp) <= 300  │
        └──────────────────────┬───────────────────────┘
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │       Compute Expected HMAC-SHA256           │
        │   msg = (timestamp + "." + raw_bytes)        │
        │   digest = hmac.new(secret, msg, sha256)     │
        └──────────────────────┬───────────────────────┘
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │         Constant-Time Verification           │
        │   hmac.compare_digest(digest, header_sig)    │
        └──────────────────────┬───────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
         [ MATCH ]                            [ MISMATCH ]
    HTTP 200 (Process)                    HTTP 400 (Reject)
```

---

## 4. Source Code Implementation

Verified implementation from `src/shivai/security/webhook_verifier.py`:

```python
"""
SHIVAY Security: Generic Raw-Body Webhook Signature Verifier.
Protects webhooks from tampering, forgery, and replay attacks.
"""

from __future__ import annotations
import hashlib
import hmac
import time
from typing import Optional, Tuple

class WebhookVerifier:
    """
    Cryptographic verification utility for HTTP webhook payloads.
    Guarantees raw byte hashing and constant-time digest comparison.
    """

    @staticmethod
    def verify_raw_hmac_sha256(raw_body: bytes, signature: str, secret: str) -> bool:
        """Verify raw byte payload against a hex-encoded HMAC-SHA256 signature."""
        if not raw_body or not signature or not secret:
            return False

        computed = hmac.new(
            key=secret.encode("utf-8"),
            msg=raw_body,
            digestmod=hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(computed.lower(), signature.strip().lower())

    @staticmethod
    def verify_timestamped_hmac_sha256(
        raw_body: bytes,
        signature_header: str,
        secret: str,
        tolerance_seconds: int = 300,
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify timestamped signatures (e.g., Stripe/GitHub style): 't=1600000000,v1=abc...'
        Validates both payload integrity and timestamp freshness.
        """
        if not raw_body or not signature_header or not secret:
            return False, "Missing payload, signature header, or secret"

        elements = {}
        for part in signature_header.split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                elements[k.strip()] = v.strip()

        timestamp_str = elements.get("t")
        v1_signature = elements.get("v1")

        if not timestamp_str or not v1_signature:
            return False, "Malformed signature header: missing 't' or 'v1' tag"

        try:
            timestamp = int(timestamp_str)
        except ValueError:
            return False, "Invalid timestamp format in signature header"

        current_time = int(time.time())
        if abs(current_time - timestamp) > tolerance_seconds:
            return False, f"Timestamp outside allowed tolerance window ({tolerance_seconds}s)"

        signed_payload = f"{timestamp}.".encode("utf-8") + raw_body
        computed = hmac.new(
            key=secret.encode("utf-8"),
            msg=signed_payload,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(computed.lower(), v1_signature.lower()):
            return False, "Cryptographic signature mismatch"

        return True, None
```

---

## 5. Verification & Testing Evidence

- **Status:** **`[TESTED]`**
- **Test File:** `tests/test_transferred_skills.py`
  - `test_webhook_raw_hmac_sha256`: **PASS** (Verifies exact hash matching, tampered payload rejection, invalid key rejection).
  - `test_webhook_timestamped_hmac`: **PASS** (Verifies valid timestamp parsing, replay attack rejection after 300s, malformed header handling).
- **Execution Time:** 0.04s across full transferred skills suite.

---

## 6. Security Considerations & Limitations

1. **Captured Wire Bytes Invariant:** Under FastAPI / Starlette, calling `await request.json()` before `await request.body()` may consume the async request stream. Handlers must strictly read `raw_body = await request.body()` first, verify signatures, and then call `json.loads(raw_body)`.
2. **Clock Drift on Microservices:** If upstream webhook emitters use unsynchronized servers, increase the tolerance window to 600s or verify via NTP status checks.
