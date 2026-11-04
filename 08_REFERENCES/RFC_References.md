# RFC & Internet Standards References

`[RESEARCH]` `[IMPLEMENTED]`

## 1. Overview

Defensive engineering and cryptographic architectures must be grounded in formal, peer-reviewed international standards. In **SHIVAY** and **JARVIS**, security protocols, token formats, transport layers, and network validations are built in strict conformance with **Internet Engineering Task Force (IETF) Requests for Comments (RFCs)**.

This document compiles the foundational RFC specifications utilized across this codebase, detailing their mathematical formulations, architectural roles, and repository implementation mappings.

---

## 2. Cryptographic & Authentication Standards

### RFC 6238 — TOTP: Time-Based One-Time Password Algorithm
- **Status:** IETF Informational (May 2011)
- **Mathematical Specification:**
  $$TOTP = \text{HOTP}(K, T)$$
  $$T = \lfloor \frac{\text{Current Unix Time} - T_0}{X} \rfloor$$
  Where $T_0 = 0$, step size $X = 30$ seconds, and $K$ is the shared base32-encoded secret.
- **Repository Implementation:** [`03_SHIVAY_SECURITY/TOTP_Implementation.md`](file:///Users/som/Developer/Cyber_Security/03_SHIVAY_SECURITY/TOTP_Implementation.md), `shivai/src/shivai/security/totp.py`.
- **Architectural Role:** Secures administrative multi-factor authentication with $\pm 1$ step clock drift tolerance.

### RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm
- **Status:** IETF Standards Track (December 2005)
- **Specification:** Defines Dynamic Truncation (Section 5.4). Extracts a 4-bit offset from the final byte of an HMAC-SHA1 digest to select a 31-bit integer, which is then modulo $10^d$ to produce a $d$-digit code.
- **Repository Implementation:** Embedded directly in `totp.py` dynamic truncation routine.

### RFC 2104 — HMAC: Keyed-Hashing for Message Authentication
- **Status:** IETF Informational (February 1997)
- **Mathematical Specification:**
  $$\text{HMAC}(K, m) = H((K' \oplus opad) \parallel H((K' \oplus ipad) \parallel m))$$
  Where $H$ is a cryptographic hash function (SHA-256), $K'$ is derived from the key $K$, and $ipad / opad$ are inner and outer padding constants.
- **Repository Implementation:** [`02_APPLICATION_SECURITY/Webhook_Security.md`](file:///Users/som/Developer/Cyber_Security/02_APPLICATION_SECURITY/Webhook_Security.md), `shivai/src/shivai/security/webhook_verifier.py`.
- **Architectural Role:** Authenticates incoming webhooks and verifies data integrity on raw byte streams.

---

## 3. Network Transport & Public Key Infrastructure Standards

### RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
- **Status:** IETF Standards Track (August 2018)
- **Key Enhancements over TLS 1.2:**
  - Mandatory Diffie-Hellman Ephemeral key exchange (eliminates static RSA key exchange).
  - Perfect Forward Secrecy (PFS) by default.
  - Zero-RTT (0-RTT) resumption and 1-RTT standard handshake.
  - Deprecation of legacy cipher suites (RC4, 3DES, CBC-mode ciphers).
- **Repository Implementation:** [`01_CYBERSECURITY_FUNDAMENTALS/Networking_Fundamentals.md`](file:///Users/som/Developer/Cyber_Security/01_CYBERSECURITY_FUNDAMENTALS/Networking_Fundamentals.md), `jarvis-livekit-voice/scripts/generate_certs.sh`.
- **Architectural Role:** Secures all local staging servers, administrative APIs, and media signaling.

### RFC 5280 — Internet X.509 Public Key Infrastructure Certificate & CRL Profile
- **Status:** IETF Standards Track (May 2008)
- **Specification:** Governs X.509 v3 certificate formats, Subject Alternative Names (SAN), Key Usage extensions, and trust chain path validation.
- **Repository Implementation:** Dynamic OpenSSL configuration (`san.cnf`) generating SAN IP extensions (`subjectAltName = IP:172.20.10.x, DNS:localhost`) for mobile device testing.

### RFC 1918 — Address Allocation for Private Internets
- **Status:** IETF Best Current Practice (February 1996)
- **Specification:** Defines private IPv4 address allocations:
  - `10.0.0.0/8` (10.0.0.0 – 10.255.255.255)
  - `172.16.0.0/12` (172.16.0.0 – 172.31.255.255)
  - `192.168.0.0/16` (192.168.0.0 – 192.168.255.255)
- **Repository Implementation:** [`04_JARVIS_AI_SECURITY/Permission_Boundaries.md`](file:///Users/som/Developer/Cyber_Security/04_JARVIS_AI_SECURITY/Permission_Boundaries.md), `shivai/src/shivai/security/scope_guard.py`.
- **Architectural Role:** Blocked by default in OSINT tools to prevent internal server-side request forgery (SSRF).

---

## 4. Real-Time Voice & WebRTC Media Standards

### RFC 3550 — RTP: A Transport Protocol for Real-Time Applications
- **Status:** IETF Standards Track (July 2003)
- **Specification:** Governs real-time packet structure, sequence numbers, timestamps, and synchronization source (SSRC) identifiers over UDP.
- **Repository Implementation:** Transport protocol utilized by LiveKit SFU media nodes.

### RFC 3711 — The Secure Real-time Transport Protocol (SRTP)
- **Status:** IETF Standards Track (March 2004)
- **Specification:** Provides confidentiality, message authentication, and replay protection for RTP traffic. Enforces AES counter mode encryption and HMAC-SHA1 authentication tags on every audio packet.
- **Repository Implementation:** [`06_PROJECT_CASE_STUDIES/JARVIS_Case_Study.md`](file:///Users/som/Developer/Cyber_Security/06_PROJECT_CASE_STUDIES/JARVIS_Case_Study.md).

### RFC 8489 — Session Traversal Utilities for NAT (STUN)
- **Status:** IETF Standards Track (February 2020)
- **Specification:** Protocol for discovering public IP addresses and port bindings when navigating through Network Address Translation (NAT) gateways.
- **Repository Implementation:** Configured in LiveKit WebRTC client ICE agent for mobile connectivity.

---

## 5. Security Disclosure & Governance Standards

### RFC 9116 — A File Format to Aid in Security Vulnerability Disclosure (`security.txt`)
- **Status:** IETF Informational (April 2022)
- **Specification:** Standardizes machine-readable location `/.well-known/security.txt` containing contact details, encryption keys, and vulnerability disclosure policies.
- **Repository Implementation:** [`05_RESEARCH_AND_EXPERIMENTS/Security_Research.md`](file:///Users/som/Developer/Cyber_Security/05_RESEARCH_AND_EXPERIMENTS/Security_Research.md), audited by `shivai/src/shivai/security/website_auditor.py`.
