# SHIVAY Security Architecture: Autonomous Defense in Depth

## 1. Overview

**SHIVAY (शिवाय)** is an autonomous personal AI assistant and engineering intelligence system designed to manage tasks, coordinate specialized multi-agent workflows, monitor host system telemetry, execute authorized OSINT investigations, and automate development tasks. Because SHIVAY bridges untrusted natural language user prompts with operating-system tools, its security architecture must defend against both traditional software exploits and novel AI-specific vulnerabilities.

This document details SHIVAY's comprehensive security architecture, defense-in-depth pipeline, permission tiers, and automated security auditor.

---

## 2. Threat Model & Security Perimeter

SHIVAY operates across five distinct threat boundaries:

```
[ Untrusted Voice / Web / HTTP Ingress ]
                   │
                   ▼
       ┌────────────────────────┐
       │ RemotePerimeterGuard   │  <-- Rate limiting (60 RPM), brute-force IP freeze
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ InjectionGuard & Token │  <-- Constant-time auth, prompt injection detection
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │    TargetScopeGuard    │  <-- Traversal rejection, metacharacter stripping
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ Pydantic ToolRegistry  │  <-- Strict tool allowlisting & Action Permission Tiers
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │  ApprovalService Gate  │  <-- Halts Tier 2 consequential actions for screen approval
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ ControlledToolExecutor │  <-- shell=False, timeouts, 64KB output ceiling
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │     SecretRedactor     │  <-- Scrubs API keys, passwords, and PII
       └───────────┬────────────┘
                   │
                   ▼
       ┌────────────────────────┐
       │ Immutable Audit Log    │  <-- Tamper-evident SQLite event recording
       └────────────────────────┘
```

---

## 3. Core Security Subsystems

### A. Action Permission Tiers (`tool_registry.py`)
SHIVAY classifies every available tool into four enforceable Action Permission Tiers:

| Tier Level | Designation | Execution Policy | Example Tools |
| :---: | :--- | :--- | :--- |
| **Tier 0** | **Read-Only** | Runs automatically with zero state mutation. | `get_project_status`, `list_deadlines`, `get_current_time`, `dns_lookup`, `whois_lookup` |
| **Tier 1** | **Reversible** | Auto-runs with full audit logging; safe to undo. | `create_task`, `set_reminder`, `create_workspace_note`, `open_allowlisted_app` |
| **Tier 2** | **Confirm-First** | **Hard-blocks automated execution.** Requires explicit human confirmation on dashboard screen. | `run_approved_shortcut`, `emergency_pause`, `dispatch_call`, `lab_destructive_reset`, `live_merge` |
| **Tier 3** | **Forbidden** | Hard-blocked in code. Never executed under any circumstance. | Arbitrary shell scripts, raw disk formatting, deleting root directories |

### B. Anti-Acoustic Voice Spoofing Guard
Because telephone audio and room microphones can be recorded, synthetically generated, or triggered by background speech (e.g. TV broadcasts), SHIVAY enforces an anti-acoustic spoofing invariant:
- **Rule:** Consequential Tier 2 actions (`approve_request`, `execute_scan`, `trash_files`) **cannot be confirmed by voice alone**.
- **Implementation:** Spoken phrases like "approve request" or "confirm action" trigger an immediate voice response:
  > *"For your safety, Som, consequential Tier 2 actions cannot be approved by voice alone. Please tap the Approve button directly on your dashboard screen to confirm."*

### C. The Emergency Pause Switch (`emergency_pause`)
The system incorporates an instantaneous kill-switch:
- When activated (`emergency_pause = True`), all tool executions, scheduled morning briefings, outbound telephony calls, and database write operations are immediately frozen.
- All mutating API requests return `HTTP 503 Service Unavailable`.
- Can be activated verbally ("SHIVAY freeze", "Emergency pause") or via dashboard button.

### D. 20-Pillar Automated Web Security Auditor (`website_auditor.py`)
SHIVAY includes an automated, agentic web application security auditor that evaluates web targets across 20 distinct security pillars:
1. TLS 1.3 / Cipher Suite Strength
2. Certificate Validity & Expiration
3. Certificate Transparency (CT) Logging
4. Content Security Policy (CSP) Directives
5. HTTP Strict Transport Security (HSTS)
6. X-Frame-Options (Clickjacking defense)
7. X-Content-Type-Options (MIME sniffing)
8. Referrer-Policy Configuration
9. Permissions-Policy Restrictions
10. Cookie Security (`HttpOnly`, `Secure`, `SameSite=Strict`)
11. CORS Header Exposure (`Access-Control-Allow-Origin: *` detection)
12. Server Banner Disclosure (Leakage of Apache/Nginx/PHP versions)
13. DNSSEC Validation
14. SPF / DMARC Email Spoofing Records
15. Open Redirect Vulnerabilities
16. Directory Listing Disclosures
17. Sensitive Path Exposure (`.env`, `.git`, `/admin`)
18. Rate Limiting Responsiveness
19. Subresource Integrity (SRI) on CDN scripts
20. HTTP Method Strictness (OPTIONS, TRACE disabled)

---

## 4. Relevant Source File References

- `src/shivai/security/tool_registry.py`: Action Permission Tiers, allowlists, and Pydantic schemas.
- `src/shivai/security/scope_guard.py`: Metacharacter sanitization and target boundary checks.
- `src/shivai/security/injection_guard.py`: Adversarial prompt injection defense.
- `src/shivai/security/website_auditor.py`: 20-Pillar Automated Web Security Auditor.
- `src/shivai/security/secret_redactor.py`: Recursive credential and token scrubbing.

---

## 5. Verification & Testing Evidence

- **Status:** **`[TESTED]`**
- **Test Suites:**
  - `tests/test_api_endpoints.py`: Auth protection, emergency pause, and rate limiting (**PASS**).
  - `tests/test_macbook_jarvis_tools.py`: Tool allowlists and PathGuard traversal defense (**PASS**).
  - `tests/test_voice_dialog.py`: Anti-acoustic spoofing verbal approval block (**PASS**).
  - `tests/test_transferred_skills.py`: Transferred security primitives (**PASS**).

---

## 6. Security Recommendations

1. **Implement Hardware FIDO2 for Tier 2 Approvals:** Upgrade dashboard approval clicks to WebAuthn biometric challenges.
2. **Periodic OSINT Rate-Limit Monitoring:** Configure caching layers on crt.sh and DNS queries to prevent upstream API blacklisting during heavy investigations.
3. **Automate Certificate Expiry Alerting:** Schedule daily security scans that raise alerts when SSL/TLS certificates have less than 14 days until expiration.
