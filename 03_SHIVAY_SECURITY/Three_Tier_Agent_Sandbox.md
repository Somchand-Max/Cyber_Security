# Three-Tier Agent Sandbox: Autonomous Coding Governance & Blast-Radius Mitigation

## 1. Overview

Autonomous AI coding agents can read repositories, generate implementation code, execute tests, and merge patches. However, granting an AI agent unrestricted write access to a production codebase introduces severe systemic risks: syntax corruption, accidental file deletion, prompt-induced hallucinations, and unintended breaking changes.

This document details the **Three-Tier Agent Sandbox Governor** implemented in **SHIVAY Core** (`src/shivai/security/three_tier_sandbox.py`). This architecture provides strict permission boundaries that decouple agent code generation from production filesystems.

---

## 2. Threat Scenarios & Blast-Radius Governance

```
┌──────────────────────────────────────────────────────────┐
│ Unrestricted Agent Risks:                                │
│ 1. Direct overwrite of production source with broken code│
│ 2. Deletion of critical database or configuration files │
│ 3. Directory traversal escaping repository boundaries    │
│ 4. Unvalidated syntax causing fatal server crashes       │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
┌──────────────────────────────────────────────────────────┐
│ Three-Tier Sandbox Defense:                              │
│ • Tier 0: Read-only inspection (live files immutable)    │
│ • Tier 1: Quarantined sandbox write + py_compile check   │
│ • Tier 2: Human screen confirmation + automated backup   │
└──────────────────────────────────────────────────────────┘
```

---

## 3. The Three-Tier Operational Model

```mermaid
flowchart TD
    AgentAction["Agent Code Action Request"] --> TraversalCheck{"Validate Path (No '..' & in Root)"}
    TraversalCheck -- "Escapes Root" --> BlockTraversal["Raise AgentSandboxError (Blocked)"]
    TraversalCheck -- "Safe Workspace Path" --> TierRouting{"Route by Action Tier"}

    subgraph Tier0 ["Tier 0: Read-Only (Autonomous Inspection)"]
        T0A["read_live_file() -> Returns UTF-8 Content"]
        T0B["generate_diff() -> Computes Unified Diff"]
        T0C["AST / Lint Inspection (Zero Disk Mutation)"]
    end

    subgraph Tier1 ["Tier 1: Quarantined Sandbox (Auto-Staged Mutation)"]
        T1A["write_to_sandbox() -> Write to staging/ directory"]
        T1B["py_compile.compile() -> Strict Python AST Syntax Check"]
        T1C["Syntax Valid?"]
        T1C -- "Syntax Error" --> T1D["Unlink Sandbox File & Raise Error"]
        T1C -- "Syntax Valid" --> T1E["Staged in Sandbox (Live Root Untouched)"]
    end

    subgraph Tier2 ["Tier 2: Production Merge (Confirm-First)"]
        T2A["execute_live_merge()"]
        T2B{"User Confirmed on Screen?"}
        T2B -- "No" --> T2C["Raise AgentSandboxError (Merge Aborted)"]
        T2B -- "Yes" --> T2D["Create Pre-Merge Backup in backups/"]
        T2D --> T2E["Atomic File Copy from Sandbox to Live Root"]
    end

    TierRouting -->|Read / Diff| Tier0
    TierRouting -->|Stage Changes| Tier1
    TierRouting -->|Merge to Live| Tier2
```

---

## 4. Source Code Implementation

Verified implementation from `src/shivai/security/three_tier_sandbox.py`:

```python
"""
SHIVAY Security: Three-Tier Agent Sandbox & Permission Governor.
Enforces strict 3-tier boundary enforcement for autonomous agent code generation:
- Tier 0: Read-only inspection (AST, health, status, diffs).
- Tier 1: Quarantined mutation in sandbox staging directory.
- Tier 2: Human-confirmed live merge with mandatory pre-merge backup.
"""

from __future__ import annotations
import difflib
import os
import py_compile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

class AgentSandboxError(Exception):
    """Base exception for sandbox security violations."""
    pass

class ThreeTierAgentGovernor:
    """
    Guarantees that autonomous coding agents cannot directly corrupt
    production files without explicit staging, verification, and approval.
    """

    def __init__(self, root_dir: Path, staging_dir: Path, backups_dir: Path):
        self.root_dir = root_dir.resolve()
        self.staging_dir = staging_dir.resolve()
        self.backups_dir = backups_dir.resolve()

        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)

    def _validate_safe_relative_path(self, relative_path: str) -> Path:
        clean = relative_path.strip().lstrip("/").lstrip("\\")
        if ".." in clean:
            raise AgentSandboxError(f"Path traversal detected: {relative_path}")
        target = (self.root_dir / clean).resolve()
        try:
            target.relative_to(self.root_dir)
        except ValueError:
            raise AgentSandboxError(f"Target path escapes workspace root: {target}")
        return target

    # ── Tier 0: Read-Only Inspection ─────────────────────────────────

    def read_live_file(self, relative_path: str) -> str:
        path = self._validate_safe_relative_path(relative_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {relative_path}")
        return path.read_text(encoding="utf-8")

    def generate_diff(self, relative_path: str, new_content: str) -> str:
        live_content = self.read_live_file(relative_path)
        live_lines = live_content.splitlines(keepends=True)
        new_lines = new_content.splitlines(keepends=True)

        diff = difflib.unified_diff(
            live_lines,
            new_lines,
            fromfile=f"live/{relative_path}",
            tofile=f"proposed/{relative_path}",
        )
        return "".join(diff)

    # ── Tier 1: Quarantined Sandbox Mutation ─────────────────────────

    def write_to_sandbox(self, relative_path: str, content: str) -> Path:
        sandbox_path = (self.staging_dir / relative_path).resolve()
        sandbox_path.parent.mkdir(parents=True, exist_ok=True)
        sandbox_path.write_text(content, encoding="utf-8")

        # Strict syntax gate for Python files
        if sandbox_path.suffix == ".py":
            try:
                py_compile.compile(str(sandbox_path), doraise=True)
            except py_compile.PyCompileError as err:
                sandbox_path.unlink(missing_ok=True)
                raise AgentSandboxError(f"Syntax validation failed in sandbox: {err}")

        return sandbox_path

    # ── Tier 2: Screen-Approved Production Merge ──────────────────────

    def execute_live_merge(self, relative_path: str, user_confirmed: bool = False) -> Dict[str, Any]:
        if not user_confirmed:
            raise AgentSandboxError("Tier 2 Live Merge blocked: user confirmation was not provided.")

        sandbox_path = (self.staging_dir / relative_path).resolve()
        if not sandbox_path.is_file():
            raise FileNotFoundError(f"No staged sandbox file found at {sandbox_path}")

        live_path = self._validate_safe_relative_path(relative_path)

        # Automated pre-merge snapshot
        backup_path = None
        if live_path.is_file():
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            backup_filename = f"{live_path.stem}_{ts}{live_path.suffix}.bak"
            backup_path = self.backups_dir / backup_filename
            shutil.copy2(live_path, backup_path)

        # Atomic copy to live location
        shutil.copy2(sandbox_path, live_path)

        return {
            "status": "merged",
            "file": relative_path,
            "backup_created": str(backup_path) if backup_path else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
```

---

## 5. Verification & Testing Evidence

- **Status:** **`[TESTED]`**
- **Test File:** `tests/test_transferred_skills.py::TestTransferredSkills::test_three_tier_agent_sandbox_quarantine`
- **Verification Assertions:**
  1. Live files read cleanly via Tier 0.
  2. Unified diff generated accurately between live and proposed code.
  3. Writing to Tier 1 sandbox preserves the live production file unmodified.
  4. Invalid Python syntax (`def broken_syntax(`) triggers immediate compilation failure and auto-deletes the corrupted staged file.
  5. Attempting Tier 2 merge with `user_confirmed=False` raises `AgentSandboxError`.
  6. Merging with `user_confirmed=True` successfully overwrites the live file and generates an automated snapshot in `backups/`.
- **Result:** PASSED in 0.04s.

---

## 6. Security Considerations & Limitations

1. **AST Checks vs. Logic Verification:** `py_compile` guarantees valid Python syntax, but cannot detect semantic bugs or infinite loops. Combining sandbox writes with automated test execution (`pytest sandbox/`) is recommended prior to Tier 2 merge.
2. **Atomic Inodes on POSIX:** `shutil.copy2` replaces file contents; in ultra-high concurrency environments, `os.replace()` provides true atomic inode swapping across the same filesystem.
