#!/usr/bin/env python3
"""
Tests that the orchestrator routes ALL tool execution through the governance gate
(AG-06 Horizon — verify no bypass exists).

These tests exercise the orchestrator's dispatch and session-persistence plumbing without
needing the Kimi CLI or any Kali tool installed: the harness loop is driven with a stubbed
_call_kimi, and the governed executor is fed fakes for the base executor and registry.

Run: python3 -m pytest tests/test_orchestrator_governance.py -v
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "src"))

import orchestrator as orch_mod
from orchestrator import KaliKimiOrchestrator
from harness_integration import SecurityToolExecutor
from kali_tools import KaliToolAdapter, SecurityToolError
from governance.engine import GovernedExecutor
from governance.consent import ConsentGate
from governance.policy import PolicyEngine
from governance.attestation import attest_binary


# --------------------------------------------------------------------------- fakes

def _trusted_binary():
    for name in ("sh", "ls", "cat", "true", "env"):
        p = shutil.which(name)
        if p and attest_binary(p).verified:
            return p
    return None


class _FakeSpec:
    def __init__(self, permission):
        self.required_permission = permission


class _FakeExecutor:
    def __init__(self, permission):
        self.permission = permission
        self.calls = []

    def get_tool_spec(self, name):
        return _FakeSpec(self.permission)

    def execute(self, name, params):
        self.calls.append((name, params))
        return {"tool": name, "returncode": 0, "success": True, "parsed_output": {}}


class _FakeTV:
    def __init__(self, permission, binary_path):
        self.permission = permission
        self.binary_path = binary_path
        self.sha256 = None


class _FakeRegistry:
    def __init__(self, tv):
        self._tv = tv

    def get(self, name):
        return self._tv


def _orchestrator_with_governed(permission, binary_path, prompt_fn):
    base = _FakeExecutor(permission)
    gov = GovernedExecutor(
        executor=base,
        registry=_FakeRegistry(_FakeTV(permission, binary_path)),
        policy=PolicyEngine(),
        consent=ConsentGate(prompt_fn=prompt_fn, timeout=1.0),
    )
    orch = KaliKimiOrchestrator(executor=gov, work_dir=tempfile.mkdtemp())
    return orch, base, gov


# --------------------------------------------------------------------------- tests

def test_orchestrator_routes_through_governed_executor():
    """A danger-full-access proposal with consent DENIED must never reach the base
    executor, and the denial must be recorded in the audit chain."""
    b = _trusted_binary()
    if not b:
        return
    orch, base, gov = _orchestrator_with_governed(
        "danger-full-access", b, prompt_fn=lambda req: "DENY"
    )
    result = orch._execute_tool_call({"tool": "nmap_scan", "params": {"target": "10.0.0.5"}})

    assert base.calls == []                       # base executor NEVER reached
    assert result["success"] is False
    assert "consent" in result["error"]
    # audit chain contains the denied consent decision (with its nonce)
    consent_entries = [e for e in gov.audit.entries if e.payload.get("event") == "consent"]
    assert consent_entries and consent_entries[0].payload.get("result") == "denied"
    assert consent_entries[0].payload["request"]["nonce"]


def test_orchestrator_blocks_local_wrapper_without_consent():
    """The masscan/tshark wrappers (direct subprocess) must also be gated."""
    b = _trusted_binary()
    if not b:
        return
    orch, base, gov = _orchestrator_with_governed(
        "danger-full-access", b, prompt_fn=lambda req: "DENY"
    )
    result = orch._execute_tool_call({"tool": "masscan_quick", "params": {"target": "10.0.0.5"}})
    assert result["success"] is False
    assert "consent" in result["error"]


def test_orchestrator_allows_read_only_without_consent():
    """Read-only tools pass through without ever consulting Mirror_RTC."""
    orch, base, gov = _orchestrator_with_governed(
        "read-only", binary_path=None, prompt_fn=lambda req: "DENY"
    )
    result = orch._execute_tool_call({"tool": "quick_recon", "params": {"target": "10.0.0.5"}})
    assert result["success"] is True
    assert len(base.calls) == 1
    assert gov.consent.decisions == []            # consent never requested for read-only


def test_orchestrator_preserves_json_extraction_on_governance_error():
    """Malformed (non-tool-call) Kimi output must fail at extraction and never reach the
    governance layer — so no audit entries are created for it."""
    orch = KaliKimiOrchestrator(work_dir=tempfile.mkdtemp())   # default: fully governed
    orch.kimi_cli = _trusted_binary() or shutil.which("sh")    # satisfy require_kimi
    orch._call_kimi = lambda prompt, session_id=None: {
        "raw_response": "this is not json", "json_blocks": [],
        "has_tool_calls": False, "returncode": 0,
    }
    orch.run_assessment(target="10.0.0.5", task="noop", depth="quick", max_rounds=2)
    assert orch.executor.audit.entries == []      # governance never invoked


def test_orchestrator_session_audit_mirror_written():
    """Every governed session writes both results/<id>.json and audit/<id>.chain, and the
    chain is internally valid."""
    work = tempfile.mkdtemp()
    orch = KaliKimiOrchestrator(work_dir=work)
    orch.kimi_cli = _trusted_binary() or shutil.which("sh")
    orch._call_kimi = lambda prompt, session_id=None: {
        "raw_response": "done",
        "json_blocks": [{"action": "complete", "summary": "done", "findings": []}],
        "has_tool_calls": True, "returncode": 0,
    }
    orch.run_assessment(target="10.0.0.5", task="noop", depth="quick", max_rounds=1)

    results = glob.glob(os.path.join(work, "results", "*.json"))
    chains = glob.glob(os.path.join(work, "audit", "*.chain"))
    assert len(results) == 1
    assert len(chains) == 1
    with open(chains[0]) as f:
        chain = json.load(f)
    assert chain["auditor_state"]["chain_valid"] is True


# --------------------------------------------------------------------------- Task 1: no CLI bypass

def test_ungoverned_flag_removed_from_cli():
    """--ungoverned must not be an accepted CLI argument."""
    proc = subprocess.run(
        [sys.executable, "orchestrator.py", "--target", "1.1.1.1", "--ungoverned"],
        cwd=str(_REPO), capture_output=True, text=True,
    )
    assert proc.returncode != 0
    assert "unrecognized arguments" in proc.stderr


# --------------------------------------------------------------------------- Task 2: L2 discipline

def test_masscan_rate_limit_enforced():
    """masscan rate above the ceiling is rejected before any subprocess runs."""
    adapter = KaliToolAdapter()
    try:
        adapter.masscan_scan(target="10.0.0.1", rate=10 ** 9)
        assert False, "should have raised"
    except SecurityToolError as e:
        assert "exceeds MAX_MASSCAN_RATE" in str(e)


def test_tshark_interface_allowlist():
    """tshark interface outside the allowlist is rejected."""
    adapter = KaliToolAdapter()
    try:
        adapter.tshark_capture(interface="docker0")
        assert False, "should have raised"
    except SecurityToolError as e:
        assert "not in allowed set" in str(e)


def test_masscan_tshark_registered_in_harness():
    """masscan/tshark are now first-class harness tools (no direct-subprocess bypass)."""
    ex = SecurityToolExecutor()
    assert "masscan_quick" in ex.tools
    assert "tshark_capture" in ex.tools
    assert ex.tools["masscan_quick"].required_permission == "danger-full-access"
    # The orchestrator no longer has direct-subprocess wrappers.
    assert not hasattr(KaliKimiOrchestrator, "_run_masscan")
    assert not hasattr(KaliKimiOrchestrator, "_run_tshark")


# --------------------------------------------------------------------------- Task 3: snap-back

def test_snap_back_restores_on_failure():
    """Restoring a snapshot rolls the workspace back to its pre-execution state."""
    orch = KaliKimiOrchestrator(work_dir=tempfile.mkdtemp())
    ws = orch._workspace_dir()
    ws.mkdir(parents=True)
    (ws / "important.txt").write_text("preserve me")

    snap = orch._create_snap(ws)
    assert snap is not None
    # Simulate a tool corrupting the workspace mid-run.
    (ws / "important.txt").write_text("CORRUPTED")
    (ws / "junk.txt").write_text("partial write")

    orch._restore_snap(ws, snap)
    assert (ws / "important.txt").read_text() == "preserve me"
    assert not (ws / "junk.txt").exists()


def test_snap_refuses_repo_root_and_vcs():
    """Snap must never copy the repo root or a directory holding a VCS checkout."""
    work = tempfile.mkdtemp()
    orch = KaliKimiOrchestrator(work_dir=work)
    # work_dir itself is refused
    assert orch._create_snap(Path(work)) is None
    # a directory containing .git is refused
    d = Path(work) / "repoish"
    (d / ".git").mkdir(parents=True)
    assert orch._create_snap(d) is None
