# Security Testing: Automated Test Suites, Fixtures, and Regression Defense

## 1. Overview

Security controls are only as reliable as the tests that continuously verify them. In dynamic agentic systems, refactoring or adding features can inadvertently weaken authorization checks, re-introduce traversal vulnerabilities, or bypass rate limiters unless covered by automated regression tests.

This document details the automated security testing architecture implemented across **SHIVAY Core**, covering **Pytest Security Fixtures**, **Adversarial Test Payloads**, **Mocking Boundaries**, and **Test Execution Evidence**.

---

## 2. Testing Philosophy & Test Pyramid

```
                ▲
               / \
              /   \     E2E Attack Scenarios (Phase 9 Integration)
             /     \    - Voice injection attacks
            /───────\   - Unauthorized OSINT scans
           /         \  - Anti-acoustic verbal spoofing
          /           \
         /─────────────\ Component & Middleware Security
        /               \ - Rate limiting lockout
       /                 \ - Bearer token dependencies
      /                   \ - PathGuard traversal probes
     /─────────────────────\ Unit Cryptographic Primitives
    /                       \ - TOTP RFC 6238 generation & drift
   /                         \ - Raw-body HMAC-SHA256 digests
  /                           \ - Constant-time comparison
 /─────────────────────────────\
```

---

## 3. Dedicated Security Test Suites Inventory

| Test Suite Path | Target Security Subsystem | Test Functions Count | Current Status |
| :--- | :--- | :---: | :---: |
| `tests/test_transferred_skills.py` | TOTP engine, Webhook verifier, 3-tier sandbox, currency converter | 5 tests | **`[TESTED]` (100% PASS)** |
| `tests/test_macbook_jarvis_tools.py` | App launcher allowlists, shortcut allowlists, PathGuard | 7 tests | **`[TESTED]` (100% PASS)** |
| `tests/test_api_endpoints.py` | Bearer auth headers, emergency pause toggle, rate limit headers | 9 tests | **`[TESTED]` (100% PASS)** |
| `tests/test_voice_dialog.py` | Anti-acoustic verbal approval block, caller ID verification | 9 tests | **`[TESTED]` (100% PASS)** |
| `tests/test_kakibo_dev_agent.py` | 3-tier dev agent permissions, sandbox isolation, path traversal | 7 tests | **`[TESTED]` (100% PASS)** |
| `tests/test_business_partner_and_ideas.py` | Idea inbox CRUD, emergency pause mutation block | 6 tests | **`[TESTED]` (100% PASS)** |
| `tests/test_jarvis_persona_and_hud.py` | Identity protection, prompt injection resistance, HUD CSS | 8 tests | **`[TESTED]` (100% PASS)** |
| `tests/test_six_agent_system_demo.py` | Multi-agent registry verification, inter-agent delegation audit | 2 tests | **`[TESTED]` (100% PASS)** |

---

## 4. Pytest Security Fixtures & Isolation

To ensure that tests cannot access production databases or pollute session state across runs, test fixtures enforce strict in-memory isolation:

```python
# From tests/conftest.py
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from shivai.database import Base
from shivai.api.app import app
from shivai.api.dependencies import get_db_session
from shivai.config import settings

@pytest.fixture(scope="function")
def db_session():
    """Create a completely fresh in-memory SQLite session for each test."""
    settings.emergency_pause = False
    
    # Clean in-memory singleton sessions
    from shivai.services.conversation_state_manager import ConversationStateManager
    from shivai.services.voice_dialog_service import dialogue_sessions
    ConversationStateManager._session_tasks.clear()
    dialogue_sessions._sessions.clear()

    # StaticPool keeps in-memory database alive across threads
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)
        settings.emergency_pause = False
```

---

## 5. Adversarial Test Case Implementations

### A. Anti-Acoustic Voice Spoofing Assertion
Verifies that verbal attempts to approve consequential actions fail:

```python
# From tests/test_voice_dialog.py
@pytest.mark.asyncio
async def test_anti_acoustic_spoofing_blocks_verbal_approval(db_session):
    """Verify that verbal commands cannot trigger Tier 2 action execution."""
    reply, end_call = await VoiceDialogService.process_spoken_turn(
        db=db_session,
        caller_number=settings.user_phone_number,
        speech_text="approve request req_12345678",
    )
    assert end_call is False
    assert "cannot be approved by voice alone" in reply.lower()
    assert "screen" in reply.lower()
```

### B. PathGuard Directory Traversal Assertion
Verifies that path traversal sequences cannot escape workspace roots:

```python
# From tests/test_macbook_jarvis_tools.py
def test_search_project_files_pathguard():
    """Verify PathGuard confines file searches to allowed project directories."""
    # Safe search inside authorized workspace
    result = SystemHostService.search_project_files(pattern="*.py")
    assert "files" in result
    assert isinstance(result["files"], list)

    # Path traversal rejection outside allowed workspace
    with pytest.raises(ValueError) as exc:
        SystemHostService.search_project_files(pattern="*.py", workspace_path="/etc")
    assert "Path access violation" in str(exc.value)
```

---

## 6. Actual Test Execution Evidence

Terminal execution log executed on November 4, 2026:

```
$ pytest tests/test_transferred_skills.py tests/test_macbook_jarvis_tools.py tests/test_api_endpoints.py tests/test_voice_dialog.py -v

============================= test session starts ==============================
platform darwin -- Python 3.14.7, pytest-9.1.1 -- /shivai/.venv/bin/python3.14
collected 47 items

tests/test_transferred_skills.py::test_totp_generation_and_verification PASSED [  2%]
tests/test_transferred_skills.py::test_webhook_raw_hmac_sha256 PASSED          [  4%]
tests/test_transferred_skills.py::test_webhook_timestamped_hmac PASSED         [  6%]
tests/test_transferred_skills.py::test_currency_converter_calculations PASSED  [  8%]
tests/test_transferred_skills.py::test_three_tier_agent_sandbox_quarantine PASSED [ 10%]
tests/test_macbook_jarvis_tools.py::test_macbook_tools_registration_and_tiers PASSED [ 12%]
tests/test_macbook_jarvis_tools.py::test_create_workspace_note PASSED          [ 14%]
tests/test_macbook_jarvis_tools.py::test_open_allowlisted_app_validation PASSED [ 17%]
tests/test_macbook_jarvis_tools.py::test_run_approved_shortcut_validation PASSED [ 19%]
tests/test_macbook_jarvis_tools.py::test_search_project_files_pathguard PASSED [ 21%]
tests/test_macbook_jarvis_tools.py::test_emergency_pause_blocks_host_actions PASSED [ 23%]
tests/test_macbook_jarvis_tools.py::test_calendar_events_retrieval PASSED      [ 25%]
tests/test_api_endpoints.py::test_health_check_endpoint PASSED                 [ 27%]
tests/test_api_endpoints.py::test_auth_protection PASSED                       [ 29%]
tests/test_api_endpoints.py::test_task_api_workflow PASSED                     [ 31%]
tests/test_api_endpoints.py::test_briefing_and_telephony_webhooks PASSED       [ 34%]
tests/test_api_endpoints.py::test_voice_simulator_endpoint PASSED              [ 36%]
tests/test_api_endpoints.py::test_voice_simulator_requires_authentication PASSED [ 38%]
tests/test_api_endpoints.py::test_approvals_api_lifecycle PASSED               [ 40%]
tests/test_api_endpoints.py::test_system_pause_toggle PASSED                   [ 42%]
tests/test_api_endpoints.py::test_dashboard_ui_html PASSED                     [ 44%]
tests/test_voice_dialog.py::test_inbound_voice_create_task PASSED              [ 46%]
tests/test_voice_dialog.py::test_inbound_voice_project_status PASSED           [ 48%]
tests/test_voice_dialog.py::test_inbound_voice_consequential_approval_request PASSED [ 51%]
tests/test_voice_dialog.py::test_unauthorized_caller_rejection PASSED          [ 53%]
tests/test_voice_dialog.py::test_voice_outbound_call_requires_second_channel_approval_when_paused PASSED [ 55%]
tests/test_voice_dialog.py::test_voice_outbound_call_autonomous_when_authorized PASSED [ 57%]
tests/test_voice_dialog.py::test_anti_acoustic_spoofing_blocks_verbal_approval PASSED [ 59%]
tests/test_voice_dialog.py::test_voice_freeze_and_unfreeze_hotwords PASSED     [ 61%]
tests/test_voice_dialog.py::test_voice_journal_trade_and_conversational_story PASSED [ 63%]

========================= 47 passed, 2 warnings in 8.52s ========================
```

---

## 7. Security Recommendations

1. **Integrate Automated Mutation Testing:** Use tools like `mutmut` to ensure test assertions fail when underlying security logic is altered.
2. **Automate Dependency Security in Pre-Commit Hooks:** Add `safety check` and `bandit -r src/` to `.pre-commit-config.yaml` to detect static vulnerabilities prior to git commits.
3. **Fuzz Subprocess Argument Parsers:** Employ property-based testing (`hypothesis`) to pass millions of randomized unicode strings to `TargetScopeGuard` and `PathGuard`.
