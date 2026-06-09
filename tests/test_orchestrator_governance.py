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
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "src"))

import orchestrator as orch_mod
from orchestrator import KaliKimiOrchestrator
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
