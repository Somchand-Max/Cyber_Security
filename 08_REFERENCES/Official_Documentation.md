# Official Security Documentation & Engineering Guides

`[RESEARCH]`

## 1. Overview

This document curates official security documentation, cryptographic engineering guidelines, and reference specifications for the core technologies and libraries utilized across **SHIVAY** and **JARVIS**.

---

## 2. Python & Cryptography

### Python Cryptographic Authority (`pyca/cryptography`)
- **Official Documentation:** https://cryptography.io/en/latest/
- **Key Modules Utilized:**
  - `cryptography.hazmat.primitives.ciphers.aead.AESGCM`: Authenticated Encryption with Associated Data (AEAD) providing 256-bit confidentiality and integrity.
  - `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`: Password-Based Key Derivation Function 2 with HMAC-SHA256 and 600,000 iterations for secure master key derivation.
  - `cryptography.hazmat.primitives.hashes`: Standard cryptographic hashing interfaces.
- **Security Guidance:** Avoid electronic codebook (ECB) mode; always utilize AEAD ciphers (AES-GCM or ChaCha20-Poly1305); ensure 96-bit initialization vectors (IVs) are never repeated with the same key.

### Python Standard Library (`hashlib`, `hmac`, `secrets`)
- **`secrets` Module:** https://docs.python.org/3/library/secrets.html (Cryptographically strong pseudo-random number generator utilizing `/dev/urandom` / `arc4random`).
- **`hmac` Module:** https://docs.python.org/3/library/hmac.html (Keyed-hashing implementation conforming to RFC 2104).
- **Security Note on Timing Attacks:** Always use `hmac.compare_digest(a, b)` rather than standard `==` operators when comparing hashes or signatures to prevent timing side-channel attacks.

---

## 3. Web Frameworks & API Security

### FastAPI & Starlette Security
- **Official Security Guide:** https://fastapi.tiangolo.com/tutorial/security/
- **Key Capabilities Utilized:**
  - `fastapi.security.OAuth2PasswordBearer`: Bearer token authorization schemes.
  - `fastapi.middleware.cors.CORSMiddleware`: Explicit cross-origin request policies.
  - `starlette.middleware.base.BaseHTTPMiddleware`: Interception layer for token bucket rate limiting and defensive security headers.
- **Pydantic Data Validation:** https://docs.pydantic.dev/latest/ (Strict schema parsing, type coercion defense, and field validation preventing unexpected properties).

---

## 4. Database & Embedded Storage

### SQLite Architecture & Write-Ahead Logging (WAL)
- **WAL Mode Documentation:** https://www.sqlite.org/wal.html
- **Pragmas for Data Integrity & Security:**
  - `PRAGMA journal_mode = WAL;`: Enables concurrent multi-reader, single-writer access with ACID durability.
  - `PRAGMA synchronous = NORMAL;`: Optimizes disk writes without compromising database integrity in WAL mode.
  - `PRAGMA foreign_keys = ON;`: Enforces relational integrity and cascading foreign key constraints.
  - `PRAGMA busy_timeout = 5000;`: Mitigates database lock contention under heavy concurrency.
- **SQLite Security Considerations:** https://www.sqlite.org/security.html (Ensuring database files are created with POSIX `0600` permissions and parameterized queries are strictly used).

---

## 5. WebRTC & Real-Time Audio Infrastructure

### LiveKit Cloud & Server Architecture
- **Official Developer Docs:** https://docs.livekit.io/
- **Security & Token Minting:** https://docs.livekit.io/home/get-started/authentication/
- **WebRTC Transport:** Encrypted RTP media transport over UDP (SRTP) negotiated via DTLS.
- **Egress & Ingress Security:** LiveKit Cloud isolates participant rooms, enforcing server-side token minting with explicit read/write grants.

### Silero VAD (Voice Activity Detection)
- **Official Repository & Benchmarks:** https://github.com/snakers4/silero-vad
- **Architecture:** Pre-trained enterprise-grade deep neural network optimized for ONNX runtime, processing 16kHz audio in 32ms frames (512 samples) to evaluate speech probability without persisting raw audio.

### ElevenLabs Streaming Audio API
- **Official API Documentation:** https://elevenlabs.io/docs/api-reference
- **Websocket Real-Time Streaming:** High-fidelity PCM/MP3 audio generation over TLS-encrypted WebSocket connections (`wss://api.elevenlabs.io`).

---

## 6. Operating System & Platform Security

### Apple macOS Security Architecture
- **Apple Platform Security Guide:** https://support.apple.com/guide/security/welcome/web
- **Key Subsystems Utilized:**
  - **LaunchServices:** macOS framework managing running applications, file associations, and background processes.
  - **Transparency, Consent, and Control (TCC):** macOS subsystem governing microphone, camera, and disk access permissions.
  - **POSIX File Locking (`fcntl.flock`):** Kernel-managed process exclusion preventing race conditions and stale PID states.
