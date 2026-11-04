# OWASP Standards & Vulnerability Cross-Reference

`[RESEARCH]` `[IMPLEMENTED]`

## 1. Overview

The Open Worldwide Application Security Project (OWASP) provides industry-standard benchmarks for software security risks. To ensure rigorous defense-in-depth, the architectures of **SHIVAY Core** and **JARVIS Voice** are mapped directly against three major OWASP standards:
1. **OWASP Top 10 Web Application Security Risks (2021)**
2. **OWASP API Security Top 10 (2023)**
3. **OWASP Top 10 for Large Language Model Applications (2025)**

This document provides a comprehensive compliance and mitigation matrix linking each OWASP risk category to the exact implementing files and architectural documentation in this repository.

---

## 2. OWASP Top 10 (2021) Web Application Security Risks

| OWASP ID | Vulnerability Category | Implemented Mitigation | Repository Documentation & Implementing Module |
| :--- | :--- | :--- | :--- |
| **A01:2021** | **Broken Access Control** | 4-Tier Permission Matrix, strict directory confinement, and manual screen approvals for Tier 2 actions | [`04_JARVIS_AI_SECURITY/Permission_Boundaries.md`](file:///Users/som/Developer/Cyber_Security/04_JARVIS_AI_SECURITY/Permission_Boundaries.md)<br>`shivai/src/shivai/security/path_guard.py` |
| **A02:2021** | **Cryptographic Failures** | TLS 1.3 encryption, PBKDF2 key derivation, AES-256-GCM AEAD, dynamic secret redactor scrubbing console logs | [`01_CYBERSECURITY_FUNDAMENTALS/Cryptography_Fundamentals.md`](file:///Users/som/Developer/Cyber_Security/01_CYBERSECURITY_FUNDAMENTALS/Cryptography_Fundamentals.md)<br>`shivai/src/shivai/security/secret_redactor.py` |
| **A03:2021** | **Injection** | Parameterized SQL queries, `shell=False` process argument tokenization, and pre-inference prompt injection regex scanner | [`02_APPLICATION_SECURITY/Input_Validation.md`](file:///Users/som/Developer/Cyber_Security/02_APPLICATION_SECURITY/Input_Validation.md)<br>`shivai/src/shivai/security/injection_guard.py` |
| **A04:2021** | **Insecure Design** | Threat modeling (STRIDE), Three-Tier Sandbox with AST verification, fail-closed security defaults | [`03_SHIVAY_SECURITY/Three_Tier_Agent_Sandbox.md`](file:///Users/som/Developer/Cyber_Security/03_SHIVAY_SECURITY/Three_Tier_Agent_Sandbox.md)<br>`shivai/src/shivai/security/three_tier_sandbox.py` |
| **A05:2021** | **Security Misconfiguration** | 20-Pillar Website Auditor, hardened headers (`CSP`, `HSTS`, `X-Frame-Options`), stripped server banners | [`05_RESEARCH_AND_EXPERIMENTS/Security_Research.md`](file:///Users/som/Developer/Cyber_Security/05_RESEARCH_AND_EXPERIMENTS/Security_Research.md)<br>`shivai/src/shivai/security/website_auditor.py` |
| **A06:2021** | **Vulnerable & Outdated Components** | Minimal dependencies, Vanilla JS frontend (0 npm packages), pinned dependency lockfiles (`uv.lock`) | [`07_LESSONS_AND_ARCHITECTURE/Architecture_Decisions.md`](file:///Users/som/Developer/Cyber_Security/07_LESSONS_AND_ARCHITECTURE/Architecture_Decisions.md) |
| **A07:2021** | **Identification & Auth Failures** | RFC 6238 TOTP MFA, 15-minute token TTL, brute-force lockout thresholds | [`03_SHIVAY_SECURITY/TOTP_Implementation.md`](file:///Users/som/Developer/Cyber_Security/03_SHIVAY_SECURITY/TOTP_Implementation.md)<br>`shivai/src/shivai/security/totp.py` |
| **A08:2021** | **Software & Data Integrity Failures** | Raw wire-byte HMAC-SHA256 webhook signatures, AST syntax validation prior to git commits | [`03_SHIVAY_SECURITY/Webhook_Verification.md`](file:///Users/som/Developer/Cyber_Security/03_SHIVAY_SECURITY/Webhook_Verification.md)<br>`shivai/src/shivai/security/webhook_verifier.py` |
| **A09:2021** | **Security Logging & Monitoring Failures** | Append-only SQLite WAL audit logger, structured JSON event metadata, independent cloud heartbeat monitor | [`02_APPLICATION_SECURITY/Database_Security.md`](file:///Users/som/Developer/Cyber_Security/02_APPLICATION_SECURITY/Database_Security.md)<br>`shivai/src/shivai/security/audit_logger.py` |
| **A10:2021** | **Server-Side Request Forgery (SSRF)** | Strict target scope guard, RFC 1918 private IP blocking, prohibition of cloud metadata (`169.254.`) | [`04_JARVIS_AI_SECURITY/Permission_Boundaries.md`](file:///Users/som/Developer/Cyber_Security/04_JARVIS_AI_SECURITY/Permission_Boundaries.md)<br>`shivai/src/shivai/security/scope_guard.py` |

---

## 3. OWASP API Security Top 10 (2023)

| OWASP API ID | Vulnerability Name | Applied Engineering Defense |
| :--- | :--- | :--- |
| **API1:2023** | **Broken Object Level Authorization** | All task and file routes validate ownership via authenticated session context; UUID primary keys prevent predictable enumeration. |
| **API2:2023** | **Broken Authentication** | Ephemeral LiveKit JWTs with 15-minute expiration; TOTP-enforced administrative endpoints. |
| **API3:2023** | **Broken Object Property Level Auth** | Pydantic strict schemas (`BaseModel`) enforce input parameter allowlists, ignoring excess properties. |
| **API4:2023** | **Unrestricted Resource Consumption** | Sliding-window token bucket rate limiter (`RemotePerimeterMiddleware`) and strict process timeout budgets. |
| **API5:2023** | **Broken Function Level Authorization** | Administrative and destructive commands gated by `ApprovalService` requiring manual screen confirmation. |
| **API6:2023** | **Unrestricted Access to Sensitive Business Flows** | Outbound automated telephone calls restricted to verified owner whitelist; voice verbal approval rejected. |
| **API7:2023** | **Server-Side Request Forgery** | `TargetScopeGuard` validates URLs and domain syntax; prevents probing loopback or link-local endpoints. |
| **API8:2023** | **Security Misconfiguration** | CORS restricted to authenticated origins; defensive security headers configured on all FastAPI responses. |
| **API9:2023** | **Improper Inventory Management** | Centralized `ToolRegistry` maintaining versioned schemas and access tiers for all agent tools. |
| **API10:2023** | **Unsafe Consumption of APIs** | Third-party API responses parsed in isolated Pydantic models; secret keys stripped before subprocess calls. |

---

## 4. OWASP Top 10 for LLM Applications (2025)

| LLM Risk ID | Threat Category | Defense Architecture in SHIVAY & JARVIS |
| :--- | :--- | :--- |
| **LLM01** | **Prompt Injection** | XML boundary isolation (`<untrusted_content>`) + heuristic scanner (`injection_guard.py`). |
| **LLM02** | **Sensitive Information Disclosure** | Real-time stream redactor (`secret_redactor.py`) scrubbing API keys, tokens, and DB strings. |
| **LLM03** | **Supply Chain Vulnerability** | Lockfile pinning (`uv.lock`), zero-npm frontend architecture, minimal standard-library reliance. |
| **LLM04** | **Data & Model Poisoning** | In-memory staging worktree and AST parser verification prior to code acceptance. |
| **LLM05** | **Improper Output Handling** | Markdown image sanitization (stripping exfil pixels), `shell=False` command execution. |
| **LLM06** | **Excessive Agency** | Consequence gating: AI agent is restricted to Tier 0/1; Tier 2 host mutations require human screen click. |
| **LLM07** | **System Prompt Leakage** | Dual-model architecture separating system instructions from public user-facing chat context. |
| **LLM08** | **Vector & Embedding Flaws** | Content provenance tracking, hybrid keyword (BM25) and dense retrieval, similarity thresholds. |
| **LLM09** | **Misinformation** | Strict grounding against local filesystem facts and official RFC/documentation citations. |
| **LLM10** | **Unbounded Consumption** | Maximum turn budgets, token output limits, and process execution timeouts (default 30 seconds). |
