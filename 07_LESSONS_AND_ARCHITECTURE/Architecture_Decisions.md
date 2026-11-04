# Architecture Decision Records (ADRs): Security & System Design

`[IMPLEMENTED]` `[RESEARCH]`

## 1. Overview of Architecture Decision Records

An Architecture Decision Record (ADR) captures an important architectural decision made along with its context, considered alternatives, and consequences. In **SHIVAY** and **JARVIS**, security was not retrofitted as an afterthought; it was engineered into every layer through formal architectural choices.

This document compiles the core ADRs governing security boundaries, transport protocols, data storage, and agent isolation.

---

## 2. ADR-001: SQLite with Write-Ahead Logging (WAL) vs. Networked SQL Databases

- **Status:** `ACCEPTED` & `IMPLEMENTED`
- **Context:** The system requires a reliable, performant relational database for task scheduling, audit trails, approval requests, and user sessions. Options evaluated included PostgreSQL/MySQL (client-server) and SQLite (in-process).
- **Decision:** Use **SQLite** running in **Write-Ahead Logging (WAL) mode** (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;`).
- **Security Rationale:**
  1. **Zero Network Attack Surface:** Client-server databases require listening on network ports (e.g., 5432 or 3306), introducing risks of port scanning, brute-force authentication attacks, and network misconfiguration. SQLite is embedded directly into the process memory, completely eliminating network exposure.
  2. **POSIX File Permissions:** Database access is governed strictly by operating system file permissions (`chmod 600`). Only the authorized local user running the daemon can read or write to the file.
  3. **High Concurrency in WAL Mode:** WAL mode allows concurrent readers to operate without blocking writers, providing up to 50,000+ reads/sec with microsecond latency on macOS NVMe storage.
- **Consequences:** Multi-node horizontal scaling is not supported out of the box; however, for a single-tenant local AI assistant and local engineering agent, SQLite provides superior performance, simplified disaster recovery, and an unbeatable security posture.

---

## 3. ADR-002: Vanilla JavaScript & Server-Sent Events vs. Heavy Modern Frontend Frameworks

- **Status:** `ACCEPTED` & `IMPLEMENTED`
- **Context:** The administrative web interface requires real-time telemetry, visual diff rendering, approval buttons, and audio streaming. Standard modern stacks typically employ React, Next.js, or Vue with large `node_modules` dependency graphs.
- **Decision:** Implement the frontend interface using **Vanilla ECMAScript 2022, Native HTML5 Web Components, and Server-Sent Events (SSE)**, with zero external npm dependencies.
- **Security Rationale:**
  1. **Elimination of Supply-Chain Attack Surface:** Modern frontend projects often pull in thousands of transitive npm packages. Vulnerabilities like malicious lifecycle scripts, package hijacking, or typo-squatting are completely eliminated.
  2. **Zero Build Step:** HTML and JS are served directly with explicit Content Security Policies (`CSP: default-src 'self'`).
  3. **Low Latency & High Auditability:** Every single line of frontend code is human-readable and can be audited in seconds without transpilation artifacts.
- **Consequences:** UI components must be hand-crafted using modern CSS; however, frontend load times dropped to under 15ms, and supply chain exposure was reduced to zero.

---

## 4. ADR-003: Three-Tier Sandboxing with AST Verification for Autonomous Code Generation

- **Status:** `ACCEPTED` & `IMPLEMENTED`
- **Context:** The AI agent possesses autonomous coding capabilities (generating and editing Python, TypeScript, and configuration files). Granting direct write access to the working repository risks destroying project code through syntax errors or accidental overwrites.
- **Decision:** Implement a **Three-Tier Sandboxing Engine** (`three_tier_sandbox.py`):
  - **Tier 0:** Read-Only access.
  - **Tier 1:** Disposable Git worktree staging where code is checked via `ast.parse()` and automated tests are run.
  - **Tier 2:** Operator visual confirmation required before merging changes into the primary repository branch, preceded by an automatic safety snapshot.
- **Security Rationale:**
  1. **Syntax & AST Integrity:** Broken syntax or incomplete hallucinated completions are caught in Tier 1 before they ever touch production files.
  2. **Rollback Guarantee:** Because edits happen in an isolated worktree branch, discarding a failed or rejected task requires only deleting the temporary worktree (`git worktree remove --force`).
  3. **Deterministic Human Oversight:** High-consequence code changes cannot bypass the operator screen.
- **Consequences:** Adds a small computational overhead (creating temporary worktrees and running test suites), but eliminates code regression and unauthorized repository modification.

---

## 5. ADR-004: Anti-Acoustic Voice Spoofing Guard: Decoupling Voice Intent from Screen Approval

- **Status:** `ACCEPTED` & `IMPLEMENTED`
- **Context:** Voice assistants are susceptible to acoustic spoofing (background loudspeakers, TV audio, ultrasound injection, or conversational misunderstandings).
- **Decision:** Voice input may **propose and stage** consequential tasks, but **voice audio is strictly prohibited from authorizing Tier 2 actions**. Approvals must be executed via the visual dashboard screen.
- **Security Rationale:**
  1. Prevents unauthorized execution triggered by audio playing in the environment.
  2. Protects against LLM conversational misinterpretations (*"Did you say approve? Yes"*) from triggering irreversible commands.
  3. Enforces visual diff inspection before execution.
- **Consequences:** The user must look at and tap their screen to approve destructive operations, trading total hands-free convenience for absolute system security.

---

## 6. ADR-005: Outbound Telephony Allowlisting & Independent Cloud Heartbeat Monitoring

- **Status:** `ACCEPTED` & `IMPLEMENTED`
- **Context:** JARVIS features automated telephone alerts to notify the owner of server failures or critical security alarms. Uncontrolled telephony APIs can be exploited for toll fraud or social engineering harassment.
- **Decision:** Implement a deterministic `TelephonyGuard` with an **allowlist restricted to the verified owner's number**, coupled with an independent cloud heartbeat monitor (`cloud_heartbeat_service.py`).
- **Security Rationale:**
  1. Prevents rogue prompt injections from dialling unauthorized third parties or premium-rate numbers.
  2. Phone numbers are masked in all logs and database tables (`+91 8369****02`).
  3. The heartbeat service runs as an independent daemon, verifying host availability without depending on the host's own internal loops.
- **Consequences:** Third-party emergency notifications require manual administrative configuration and cannot be added dynamically by the AI agent.
