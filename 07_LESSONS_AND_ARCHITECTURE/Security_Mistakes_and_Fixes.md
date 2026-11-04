# Security Post-Mortems: Real-World Vulnerabilities, Mistakes, & Remediations

`[TESTED]` `[IMPLEMENTED]`

## 1. The Value of Transparent Security Post-Mortems

A robust cybersecurity posture is not built on theoretical perfection; it is forged by identifying, diagnosing, and permanently eliminating real-world implementation flaws. Transparently documenting bugs, race conditions, and cryptographic traps provides invaluable insight for systems engineers and cybersecurity practitioners.

This document details five significant security bugs, network bottlenecks, and logic traps encountered during the engineering of **SHIVAY** and **JARVIS**, along with their technical root causes and verified remediations.

---

## 2. Post-Mortem 1: Python Scoping Shadowing & UnboundLocalError Crash

### The Vulnerability & Symptom
During voice interaction acceptance tests in JARVIS, speaking the query *"JARVIS, what is the status of my active tasks?"* caused the voice dialog service to crash with an unhandled exception:
```text
UnboundLocalError: cannot access local variable 'TaskStatus' where it is not associated with a value
File "shivai/src/shivai/services/voice_dialog_service.py", line 538, in handle_voice_turn
```
This resulted in a Denial of Service (DoS) of the real-time voice pipeline.

### Root Cause Analysis
In Python, if a variable is assigned to or imported anywhere inside a function scope, Python marks that variable as local to the entire function at compile time.

```python
# VULNERABLE CODE (Simplified snippet from voice_dialog_service.py)
from shivai.models.task import TaskStatus  # Top-level module import

def handle_voice_turn(user_speech: str):
    # Branch A: Reads TaskStatus
    if "status" in user_speech:
        return db.query(Task).filter(Task.status == TaskStatus.IN_PROGRESS).all() # FAILS HERE!

    # Branch B: Redundant conditional local import nested deep in the function
    if "orchestrate" in user_speech:
        from shivai.models.task import TaskStatus  # Shadows top-level name across entire function!
        ...
```
Because `TaskStatus` was conditionally re-imported inside Branch B, the Python interpreter treated `TaskStatus` as a local variable for the *entire* function body. When Branch A executed, the local variable had not yet been assigned, raising `UnboundLocalError`.

### Remediation & Permanent Fix
1. Removed all redundant local imports nested inside conditional logic.
2. Consolidated all model and enum definitions (`Task`, `TaskStatus`, `TaskPriority`) at the top-level module header.
3. Added automated unit tests (`tests/services/test_voice_dialog_service.py`) executing all voice query branches to prevent variable shadowing regressions.

---

## 3. Post-Mortem 2: The Webhook Wire-Byte Serialization Trap

### The Vulnerability & Symptom
During payment webhook testing with Razorpay, legitimately signed test webhooks were repeatedly rejected with HTTP 400 `Invalid HMAC Signature`, even though the signing secret was 100% correct.

### Root Cause Analysis
The initial implementation parsed the incoming HTTP request as a JSON dictionary before verifying the signature:

```python
# VULNERABLE IMPLEMENTATION
@router.post("/webhooks/payment")
async def handle_payment(request: Request):
    payload_dict = await request.json()
    received_sig = request.headers.get("X-Razorpay-Signature")

    # Flawed re-serialization:
    serialized_str = json.dumps(payload_dict)
    computed_sig = hmac.new(SECRET.encode(), serialized_str.encode(), hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(computed_sig, received_sig):
        raise HTTPException(status_code=400, detail="Invalid signature")
```

**Why it failed:**
- Standard JSON serialization in Python `json.dumps()` adds trailing spaces after delimiters by default (`", "` instead of `","`).
- Floating-point amounts (e.g., `499.00`) are often parsed by JSON engines as numbers, stripping trailing zeroes (`499.0`).
- Because cryptographic hash functions possess the **avalanche effect**, a single whitespace or character variation completely changes the resulting SHA-256 digest!

### Remediation & Permanent Fix
Webhook signatures must **never** be computed against re-serialized JSON. The verification engine was rewritten to read the **raw bytes directly off the incoming network stream**:

```python
# REMEDIATED IMPLEMENTATION (shivai/src/shivai/security/webhook_verifier.py)
@router.post("/webhooks/payment")
async def handle_payment(request: Request):
    raw_body_bytes = await request.body()  # Raw wire-bytes before any JSON parsing
    received_sig = request.headers.get("X-Razorpay-Signature")

    # Cryptographic verification directly on wire bytes
    WebhookVerifier.verify_signature(
        raw_body_bytes=raw_body_bytes,
        signature_header=received_sig,
        secret=SECRET
    )
    
    # Only parse JSON after cryptographic authenticity is proven
    payload = json.loads(raw_body_bytes.decode("utf-8"))
```

---

## 4. Post-Mortem 3: Mobile TOTP Clock Drift Authentication Failures

### The Vulnerability & Symptom
Users attempting to sign in to the administrative interface using Google Authenticator on mobile cellular networks experienced intermittent login failures (roughly 20% failure rate) despite typing valid 6-digit codes.

### Root Cause Analysis
The initial RFC 6238 implementation computed the TOTP code strictly for the exact current 30-second time block:
$$T = \lfloor \frac{\text{Current Time}}{30} \rfloor$$
On mobile cellular data connections (4G/5G), mobile device clocks can drift by 10 to 15 seconds relative to NTP server time, or users may enter the code just as a 30-second boundary expires. If the mobile phone is at second 29 and the server is at second 31, the server computes a different hash, rejecting the legitimate user.

### Remediation & Permanent Fix
Expanded the verification algorithm to support **$\pm 1$ time-step clock drift tolerance**:

```python
# REMEDIATED PATTERN (shivai/src/shivai/security/totp.py)
@classmethod
def verify_totp(cls, secret: str, code: str, drift_steps: int = 1) -> bool:
    current_step = int(time.time() // 30)
    
    # Check steps: T-1 (past), T (current), T+1 (future) -> 90-second window
    for step in range(current_step - drift_steps, current_step + drift_steps + 1):
        if hmac.compare_digest(cls.generate_totp_for_step(secret, step), code):
            return True
            
    return False
```
This reduced authentication failure rates to 0% across all tested mobile devices while maintaining high cryptographic entropy (an attacker still has only a $3 \times 10^{-6}$ probability of guessing a 6-digit code).

---

## 5. Post-Mortem 4: Corporate Wi-Fi AP Client Isolation

### The Vulnerability & Symptom
During mobile browser testing on an enterprise office network, physical Android and iOS phones failed to connect to the HTTPS staging server:
- Browser reported `ERR_EMPTY_RESPONSE`.
- Local tests on the Mac (`curl https://127.0.0.1:8443` and `curl https://10.107.29.188:8443`) returned HTTP 200 OK.

### Root Cause Analysis
Enterprise 802.11 access points implement **AP Client Isolation (Intra-BSS Isolation)**. This layer 2 security feature prevents Wi-Fi clients on the same SSID from communicating with one another, protecting corporate laptops from peer malware spread. Consequently, all TCP SYN packets transmitted from the phone to the Mac's IP were silently dropped by the Wi-Fi access point before reaching the Mac's network interface.

### Remediation & Permanent Fix
1. Switched both devices to a private, dedicated **Personal Hotspot** network (`172.20.10.0/28`).
2. Because the host Mac received a new DHCP IP address (`172.20.10.2`), the previous TLS certificate became invalid (browsers enforce Subject Alternative Name IP matching).
3. Automated the regeneration of TLS 1.3 certificates dynamically containing the current active IP address via `generate_certs.sh`.
4. Mobile browser established immediate connection and WebRTC audio streamed without packet drops.

---

## 6. Post-Mortem 5: Stale PID Files & Server Port Collisions

### The Vulnerability & Symptom
When the development machine was abruptly rebooted or the development server was terminated via `kill -9`, subsequent startup attempts failed with:
```text
Error: Staging server appears to be running (PID 58516). Aborting startup.
```
However, inspecting `ps aux` showed that PID 58516 did not exist.

### Root Cause Analysis
The startup shell script used a naive file-check mechanism:
```bash
if [ -f /tmp/server.pid ]; then
    echo "Already running"
    exit 1
fi
```
If the process terminated abruptly without running its cleanup trap, the `/tmp/server.pid` file remained on disk permanently, blocking all future startups. Furthermore, if the OS subsequently assigned PID 58516 to an unrelated user process, a naive `kill $(cat /tmp/server.pid)` would kill an innocent system process!

### Remediation & Permanent Fix
Migrated from static PID text files to **POSIX kernel-managed file locks (`fcntl.flock`)**:
1. The process opens `/tmp/server.lock` and requests an exclusive non-blocking lock (`LOCK_EX | LOCK_NB`).
2. If the lock is held by another running process, the OS immediately returns `EWOULDBLOCK`.
3. If the holding process terminates (even via uncatchable `SIGKILL` or system crash), the OS kernel **automatically and immediately releases the file lock descriptor**, completely eliminating stale lockouts.
