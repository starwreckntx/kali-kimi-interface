#!/usr/bin/env python3
"""
Tests for the KKI governance layer (src/governance/).

Covers positive allowlist validation, per-invocation binary attestation, the append-only
hash-chained audit log, the permission-as-code policy engine, the Mirror_RTC consent gate,
and — most importantly — the GovernedExecutor regression suite proving that a
danger-full-access tool can never reach execution without operator consent.

Run: python3 -m pytest tests/test_governance.py -v
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from governance.validation import (
    validate_target, validate_url, validate_flags, normalize, PolicyViolation,
)
from governance.attestation import attest_binary, TRUSTED_DIRS
from governance.consent import ConsentGate, ConsentResult
from governance.audit import AuditLog
from governance.policy import PolicyEngine, Authorization, BlastRadius
from governance.engine import GovernedExecutor


# --------------------------------------------------------------------------- helpers

def _trusted_binary():
    """Return the path to a real binary that attests as verified, or None."""
    for name in ("sh", "ls", "cat", "true", "env"):
        p = shutil.which(name)
        if p and attest_binary(p).verified:
            return p
    return None


class _FakeSpec:
    def __init__(self, permission):
        self.required_permission = permission


class _FakeExecutor:
    """Records execute() calls so tests can assert it was / was not reached."""
    def __init__(self, permission):
        self.permission = permission
        self.calls = []

    def get_tool_spec(self, name):
        return _FakeSpec(self.permission)

    def execute(self, name, params):
        self.calls.append((name, params))
        return {"tool": name, "returncode": 0, "success": True}


class _FakeTV:
    def __init__(self, permission, binary_path, sha256=None):
        self.permission = permission
        self.binary_path = binary_path
        self.sha256 = sha256


class _FakeRegistry:
    def __init__(self, tv):
        self._tv = tv

    def get(self, name):
        return self._tv


def _governed(permission, binary_path=None, prompt_fn=None):
    ex = _FakeExecutor(permission)
    reg = _FakeRegistry(_FakeTV(permission, binary_path))
    gov = GovernedExecutor(
        executor=ex, registry=reg,
        consent=ConsentGate(prompt_fn=prompt_fn, timeout=1.0),
    )
    return gov, ex


# --------------------------------------------------------------------------- validation

class TestTargetValidation:
    def test_valid_ipv4(self):
        assert validate_target("192.168.1.1") == "192.168.1.1"

    def test_valid_cidr(self):
        assert validate_target("10.0.0.0/24") == "10.0.0.0/24"

    def test_valid_hostname(self):
        assert validate_target("scanme.nmap.org") == "scanme.nmap.org"

    def test_valid_ipv6(self):
        assert validate_target("::1") == "::1"

    def test_injection_rejected(self):
        for bad in ("8.8.8.8; rm -rf /", "$(whoami)", "a|b", "`id`", "1.1.1.1 && ls"):
            try:
                validate_target(bad)
                assert False, f"should have rejected {bad!r}"
            except PolicyViolation:
                pass

    def test_null_byte_rejected(self):
        try:
            validate_target("10.0.0.1\x00")
            assert False
        except PolicyViolation:
            pass

    def test_homoglyph_rejected(self):
        # Cyrillic 'а' (U+0430) in place of ASCII 'a' must fail the ASCII hostname regex.
        try:
            validate_target("exаmple.com")
            assert False
        except PolicyViolation:
            pass

    def test_empty_rejected(self):
        try:
            validate_target("   ")
            assert False
        except PolicyViolation:
            pass

    def test_scope_enforced_in_scope(self):
        assert validate_target("10.1.2.3", scope=["10.0.0.0/8"]) == "10.1.2.3"

    def test_scope_enforced_out_of_scope(self):
        try:
            validate_target("8.8.8.8", scope=["10.0.0.0/8"])
            assert False
        except PolicyViolation:
            pass


class TestFlagValidation:
    def test_valid_nmap_flags(self):
        assert validate_flags("nmap", "-sS -p 1-100") == ["-sS", "-p", "1-100"]

    def test_disallowed_flag_rejected(self):
        try:
            validate_flags("nmap", "-sS --script=evil.nse")
            assert False
        except PolicyViolation:
            pass

    def test_value_with_metachar_rejected(self):
        try:
            validate_flags("nmap", "-p 1-100;ls")
            assert False
        except PolicyViolation:
            pass

    def test_unknown_tool_fails_closed(self):
        try:
            validate_flags("totally-unknown-tool", "-x")
            assert False
        except PolicyViolation:
            pass

    def test_empty_flags_ok(self):
        assert validate_flags("nmap", "") == []


class TestUrlValidation:
    def test_valid_url(self):
        assert validate_url("http://example.com/app?id=1") == "http://example.com/app?id=1"

    def test_bad_scheme_rejected(self):
        try:
            validate_url("file:///etc/passwd")
            assert False
        except PolicyViolation:
            pass

    def test_injection_host_rejected(self):
        try:
            validate_url("http://a;b.com/")
            assert False
        except PolicyViolation:
            pass


# --------------------------------------------------------------------------- attestation

class TestAttestation:
    def test_trusted_binary_verifies(self):
        b = _trusted_binary()
        if not b:
            return  # no trusted binary available in this environment
        att = attest_binary(b)
        assert att.installed and att.in_trusted_dir and att.verified

    def test_untrusted_path_rejected(self):
        with tempfile.NamedTemporaryFile(prefix="evil-", suffix="-tool", delete=False) as f:
            f.write(b"#!/bin/sh\necho pwned\n")
            path = f.name
        os.chmod(path, 0o755)
        try:
            att = attest_binary(path)
            assert att.installed
            assert not att.in_trusted_dir
            assert not att.verified
        finally:
            os.unlink(path)

    def test_missing_binary(self):
        att = attest_binary("definitely-not-a-real-binary-xyz")
        assert not att.installed and not att.verified

    def test_hash_mismatch_rejected(self):
        b = _trusted_binary()
        if not b:
            return
        att = attest_binary(b, expected_sha256="00" * 32)
        assert att.hash_matches is False
        assert not att.verified


# --------------------------------------------------------------------------- audit

class TestAuditLog:
    def test_chain_verifies(self):
        log = AuditLog()
        log.log_decision({"a": 1})
        log.log_execution({"b": 2})
        log.log_integrity({"c": 3})
        ok, bad = log.verify()
        assert ok and bad is None
        assert log.auditor_state()["chain_valid"] is True

    def test_tamper_detected(self):
        log = AuditLog()
        log.log_decision({"a": 1})
        log.log_execution({"b": 2})
        # Mutate a payload after the fact — the chain hash must no longer match.
        log._entries[0].payload["a"] = 999
        ok, bad = log.verify()
        assert not ok and bad == 0

    def test_save(self):
        log = AuditLog()
        log.log_decision({"a": 1})
        with tempfile.TemporaryDirectory() as d:
            path = log.save(os.path.join(d, "sub", "audit.json"))
            assert os.path.exists(path)


# --------------------------------------------------------------------------- policy

class TestPolicyEngine:
    def test_read_only_granted(self):
        d = PolicyEngine().evaluate("quick_recon", "read-only", {"target": "10.0.0.1"})
        assert d.authorization == Authorization.GRANTED
        assert d.blast_radius == BlastRadius.RECON

    def test_workspace_write_granted(self):
        d = PolicyEngine().evaluate("recon-ng", "workspace-write", {"target": "10.0.0.1"})
        assert d.authorization == Authorization.GRANTED

    def test_danger_requires_consent(self):
        d = PolicyEngine().evaluate("nmap_scan", "danger-full-access", {"target": "10.0.0.1"})
        assert d.authorization == Authorization.REQUIRES_CONSENT
        assert d.blast_radius == BlastRadius.DANGER

    def test_invalid_target_denied(self):
        d = PolicyEngine().evaluate("nmap_scan", "danger-full-access", {"target": "1.1.1.1; rm -rf /"})
        assert d.authorization == Authorization.DENIED

    def test_unknown_permission_fails_closed(self):
        d = PolicyEngine().evaluate("mystery", "made-up", {"target": "10.0.0.1"})
        assert d.blast_radius == BlastRadius.DANGER
        assert d.authorization == Authorization.REQUIRES_CONSENT


# --------------------------------------------------------------------------- consent

class TestConsentGate:
    def test_approve_with_correct_nonce(self):
        gate = ConsentGate(prompt_fn=lambda req: f"APPROVE {req.nonce}")
        d = gate.request("nmap", "10.0.0.1", "danger")
        assert d.approved and d.result == ConsentResult.APPROVED

    def test_deny(self):
        gate = ConsentGate(prompt_fn=lambda req: "DENY")
        d = gate.request("nmap", "10.0.0.1", "danger")
        assert not d.approved and d.result == ConsentResult.DENIED
        assert len(gate.unauthorized) == 1

    def test_wrong_nonce_denied(self):
        gate = ConsentGate(prompt_fn=lambda req: "APPROVE deadbeef")
        d = gate.request("nmap", "10.0.0.1", "danger")
        assert not d.approved

    def test_no_response_not_approved(self):
        gate = ConsentGate(prompt_fn=lambda req: None)
        d = gate.request("nmap", "10.0.0.1", "danger")
        assert not d.approved

    def test_boundary_report(self):
        gate = ConsentGate(prompt_fn=lambda req: "DENY")
        gate.request("nmap", "10.0.0.1", "danger")
        report = gate.boundary_report()
        assert report["total_requests"] == 1
        assert report["approved"] == 0
        assert len(report["unauthorized"]) == 1


# --------------------------------------------------------------------------- GOVERNANCE REGRESSION

class TestGovernedExecutorRegression:
    """The non-negotiable invariant: DANGER never executes without operator consent."""

    def test_danger_blocked_when_consent_denied(self):
        b = _trusted_binary()
        if not b:
            return
        gov, ex = _governed("danger-full-access", binary_path=b, prompt_fn=lambda req: "DENY")
        out = gov.execute("nmap_scan", {"target": "10.0.0.5"})
        assert out.allowed is False
        assert out.result is None
        assert ex.calls == []                       # underlying executor NEVER reached
        assert "consent" in (out.denial_reason or "")

    def test_danger_blocked_when_no_operator(self):
        b = _trusted_binary()
        if not b:
            return
        gov, ex = _governed("danger-full-access", binary_path=b, prompt_fn=lambda req: None)
        out = gov.execute("nmap_scan", {"target": "10.0.0.5"})
        assert out.allowed is False
        assert ex.calls == []

    def test_danger_runs_only_after_approval(self):
        b = _trusted_binary()
        if not b:
            return
        gov, ex = _governed("danger-full-access", binary_path=b,
                            prompt_fn=lambda req: f"APPROVE {req.nonce}")
        out = gov.execute("nmap_scan", {"target": "10.0.0.5"})
        assert out.allowed is True
        assert len(ex.calls) == 1                   # executed exactly once, after consent

    def test_injection_denied_before_execution(self):
        gov, ex = _governed("danger-full-access", binary_path=_trusted_binary(),
                            prompt_fn=lambda req: f"APPROVE {req.nonce}")
        out = gov.execute("nmap_scan", {"target": "10.0.0.5; rm -rf /"})
        assert out.allowed is False
        assert ex.calls == []                       # blocked at policy, never prompted/run

    def test_read_only_runs_without_consent(self):
        gov, ex = _governed("read-only", binary_path=None, prompt_fn=lambda req: "DENY")
        out = gov.execute("quick_recon", {"target": "10.0.0.5"})
        assert out.allowed is True
        assert len(ex.calls) == 1
        assert gov.consent.decisions == []          # consent never requested for read-only

    def test_audit_trail_intact_after_run(self):
        gov, ex = _governed("read-only", prompt_fn=lambda req: "DENY")
        gov.execute("quick_recon", {"target": "10.0.0.5"})
        ok, bad = gov.audit.verify()
        assert ok and bad is None
        assert len(gov.audit.entries) >= 3          # decision + policy + attestation + execution
