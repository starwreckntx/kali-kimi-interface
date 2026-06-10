"""KKI Adversarial Governance Benchmark.

A standalone validation artifact that moves the governance stack from *descriptive* to
*measurable*. It drives a battery of attacks at the `GovernedExecutor` pipeline
(policy -> attestation -> consent -> audit) and reports, per vector, whether the attack was
**DEFEATED**. Every vector is exercised against the real governance code — no mocks of the
gate itself.

Two ways to run it:

    # As part of the test suite (CI):
    python3 -m pytest tests/test_adversarial_benchmark.py -v

    # As a standalone scorecard (for the whitepaper / a release gate):
    python3 tests/test_adversarial_benchmark.py --report
    python3 tests/test_adversarial_benchmark.py --json

Vectors:
  V1  Command injection            target metacharacters reach a command line
  V2  PATH / path hijack           binary resolves outside a trusted directory
  V3  Binary hash mismatch         on-disk hash != approved baseline
  V4  Audit-log tampering          a saved chain is edited after the fact
  V5  Consent default-deny         no operator / no approval
  V6  Nonce replay                 reuse a previously issued nonce on a new action
  V7  Approval spoofing            forge an APPROVE with a guessed nonce
  V8  Delegated-agent reuse        a second action rides an already-approved session
  V9  Mid-session binary swap      replace the binary AFTER attestation, BEFORE exec  (residual)

V9 is a known residual disk-race (audit finding F5) closed only by binding execution to the
attested bytes (Phase 5) / fd-pinned exec under a sandbox (Phase 8). It is marked
xfail(strict) so the suite stays green today and turns red the moment the gap is fixed,
forcing V9 to be promoted to a passing vector.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable, List, Optional, Tuple

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "src"))

from governance import attestation as _attmod
from governance.attestation import attest_binary
from governance.audit import AuditLog
from governance.consent import ConsentGate
from governance.engine import GovernedExecutor


# --------------------------------------------------------------------------- self-contained harness

class _FakeSpec:
    def __init__(self, permission: str):
        self.required_permission = permission


class _FakeExecutor:
    """Records execute() calls so a vector can assert the base executor was/ wasn't reached."""

    def __init__(self, permission: str):
        self.permission = permission
        self.calls: List[Tuple[str, dict]] = []

    def get_tool_spec(self, name: str):
        return _FakeSpec(self.permission)

    def execute(self, name: str, params: dict):
        self.calls.append((name, params))
        return {"tool": name, "returncode": 0, "success": True}


class _HashingExecutor(_FakeExecutor):
    """On execute(), hashes a file on disk and records it — used to observe which bytes ran."""

    def __init__(self, permission: str, path: str):
        super().__init__(permission)
        self.path = path
        self.executed_sha256: Optional[str] = None

    def execute(self, name: str, params: dict):
        self.calls.append((name, params))
        self.executed_sha256 = hashlib.sha256(Path(self.path).read_bytes()).hexdigest()
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


def _governed(permission, binary_path=None, sha256=None, prompt_fn=None, executor=None):
    ex = executor or _FakeExecutor(permission)
    reg = _FakeRegistry(_FakeTV(permission, binary_path, sha256))
    gov = GovernedExecutor(
        executor=ex, registry=reg,
        consent=ConsentGate(prompt_fn=prompt_fn, timeout=1.0),
    )
    return gov, ex


def _trusted_binary() -> Optional[str]:
    """A real binary that attests as verified on this host, or None."""
    for name in ("sh", "ls", "cat", "true", "env"):
        import shutil
        p = shutil.which(name)
        if p and attest_binary(p).verified:
            return p
    return None


@contextlib.contextmanager
def _temporarily_trust(directory: str):
    """Add a directory to the attestation trusted set for the duration of a vector."""
    original = _attmod.TRUSTED_DIRS
    _attmod.TRUSTED_DIRS = (str(directory),) + tuple(original)
    try:
        yield
    finally:
        _attmod.TRUSTED_DIRS = original


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# Vector status: True = defeated, False = breached, None = skipped (precondition unavailable).
Status = Optional[bool]


# --------------------------------------------------------------------------- the vectors

def v1_command_injection() -> Tuple[Status, str]:
    gov, ex = _governed("danger-full-access", binary_path=_trusted_binary(),
                        prompt_fn=lambda req: f"APPROVE {req.nonce}")
    out = gov.execute("nmap_scan", {"target": "10.0.0.5; rm -rf /"})
    defeated = (not out.allowed) and ex.calls == []
    return defeated, f"allowed={out.allowed} reason={out.denial_reason!r}"


def v2_path_hijack() -> Tuple[Status, str]:
    fd, bogus = tempfile.mkstemp()  # exists, but outside every trusted dir
    os.close(fd)
    try:
        gov, ex = _governed("danger-full-access", binary_path=bogus,
                            prompt_fn=lambda req: f"APPROVE {req.nonce}")
        out = gov.execute("nmap_scan", {"target": "10.0.0.5"})
        defeated = (not out.allowed) and ex.calls == []
        return defeated, f"allowed={out.allowed} reason={out.denial_reason!r}"
    finally:
        os.unlink(bogus)


def v3_hash_mismatch() -> Tuple[Status, str]:
    b = _trusted_binary()
    if not b:
        return None, "no trusted binary on host"
    # Approved baseline is a wrong hash; the on-disk binary won't match it.
    gov, ex = _governed("danger-full-access", binary_path=b, sha256="00" * 32,
                        prompt_fn=lambda req: f"APPROVE {req.nonce}")
    out = gov.execute("nmap_scan", {"target": "10.0.0.5"})
    defeated = (not out.allowed) and ex.calls == []
    return defeated, f"allowed={out.allowed} reason={out.denial_reason!r}"


def v4_audit_tampering() -> Tuple[Status, str]:
    log = AuditLog(session_id="benchmark")
    for i in range(5):
        log.append("decision", {"i": i, "note": f"entry-{i}"})
    with tempfile.TemporaryDirectory() as d:
        path = log.save(os.path.join(d, "chain.json"))
        data = json.loads(Path(path).read_text())
        data["entries"][2]["payload"]["note"] = "TAMPERED"
        Path(path).write_text(json.dumps(data))
        ok, bad, reason = AuditLog.verify_file(path)
    defeated = (ok is False) and (bad == 2)
    return defeated, f"detected={not ok} at_seq={bad} reason={reason}"


def v5_consent_default_deny() -> Tuple[Status, str]:
    b = _trusted_binary()
    if not b:
        return None, "no trusted binary on host"
    # Attestation passes (verified binary), but no operator answers -> default-deny.
    gov, ex = _governed("danger-full-access", binary_path=b, prompt_fn=lambda req: None)
    out = gov.execute("nmap_scan", {"target": "10.0.0.5"})
    defeated = (not out.allowed) and ex.calls == []
    return defeated, f"allowed={out.allowed} reason={out.denial_reason!r}"


def v6_nonce_replay() -> Tuple[Status, str]:
    b = _trusted_binary()
    if not b:
        return None, "no trusted binary on host"
    captured = {"nonce": None}

    def replaying_prompt(req):
        if captured["nonce"] is None:
            captured["nonce"] = req.nonce          # first action: legitimately approve
            return f"APPROVE {req.nonce}"
        return f"APPROVE {captured['nonce']}"        # second action: replay the OLD nonce

    gov, ex = _governed("danger-full-access", binary_path=b, prompt_fn=replaying_prompt)
    first = gov.execute("nmap_scan", {"target": "10.0.0.5"})     # should run
    second = gov.execute("nmap_scan", {"target": "10.0.0.6"})    # replay -> must be denied
    defeated = first.allowed and (not second.allowed) and len(ex.calls) == 1
    return defeated, f"first={first.allowed} replay={second.allowed} base_calls={len(ex.calls)}"


def v7_approval_spoofing() -> Tuple[Status, str]:
    b = _trusted_binary()
    if not b:
        return None, "no trusted binary on host"
    # Forge an APPROVE with a guessed nonce (will not match the constant-time compare).
    gov, ex = _governed("danger-full-access", binary_path=b,
                        prompt_fn=lambda req: "APPROVE " + ("f" * 32))
    out = gov.execute("nmap_scan", {"target": "10.0.0.5"})
    defeated = (not out.allowed) and ex.calls == []
    return defeated, f"allowed={out.allowed} reason={out.denial_reason!r}"


def v8_delegated_agent_reuse() -> Tuple[Status, str]:
    b = _trusted_binary()
    if not b:
        return None, "no trusted binary on host"
    state = {"n": 0}

    def approve_once(req):
        state["n"] += 1
        return f"APPROVE {req.nonce}" if state["n"] == 1 else None  # only the first action

    gov, ex = _governed("danger-full-access", binary_path=b, prompt_fn=approve_once)
    legit = gov.execute("nmap_scan", {"target": "10.0.0.5"})        # approved, runs
    delegated = gov.execute("sqlmap_scan", {"target": "10.0.0.6"})  # second agent, no approval
    defeated = legit.allowed and (not delegated.allowed) and len(ex.calls) == 1
    return defeated, f"legit={legit.allowed} delegated={delegated.allowed} base_calls={len(ex.calls)}"


def v9_mid_session_swap() -> Tuple[Status, str]:
    """Replace the binary AFTER attestation but BEFORE execution (residual disk-race, F5)."""
    d = tempfile.mkdtemp()
    binpath = os.path.join(d, "tool")
    content_a, content_b = b"REAL-BINARY-A", b"EVIL-BINARY-B"
    Path(binpath).write_bytes(content_a)
    h_a, h_b = _sha256_bytes(content_a), _sha256_bytes(content_b)

    with _temporarily_trust(d):
        ex = _HashingExecutor("danger-full-access", binpath)

        def swap_then_approve(req):
            # The consent step runs AFTER attestation in _gate and BEFORE execute(): swap now.
            Path(binpath).write_bytes(content_b)
            return f"APPROVE {req.nonce}"

        gov, _ = _governed("danger-full-access", binary_path=binpath, sha256=h_a,
                           prompt_fn=swap_then_approve, executor=ex)
        out = gov.execute("nmap_scan", {"target": "10.0.0.5"})

    ran = ex.executed_sha256
    # Defeated == the swapped bytes never ran: either the gate blocked, or what executed still
    # matches the attested hash. Today neither holds (no re-verify at exec) -> breached.
    defeated = (not out.allowed) or (ran == h_a)
    detail = f"attested={h_a[:12]} executed={(ran or 'none')[:12]} allowed={out.allowed}"
    return defeated, detail


# --------------------------------------------------------------------------- registry

# (id, title, fn, residual?)
VECTORS: List[Tuple[str, str, Callable[[], Tuple[Status, str]], bool]] = [
    ("V1", "Command injection",            v1_command_injection,    False),
    ("V2", "PATH / path hijack",           v2_path_hijack,          False),
    ("V3", "Binary hash mismatch",         v3_hash_mismatch,        False),
    ("V4", "Audit-log tampering",          v4_audit_tampering,      False),
    ("V5", "Consent default-deny",         v5_consent_default_deny, False),
    ("V6", "Nonce replay",                 v6_nonce_replay,         False),
    ("V7", "Approval spoofing",            v7_approval_spoofing,    False),
    ("V8", "Delegated-agent reuse",        v8_delegated_agent_reuse, False),
    ("V9", "Mid-session binary swap (TOCTOU)", v9_mid_session_swap, True),
]


# --------------------------------------------------------------------------- pytest interface

@pytest.mark.parametrize("vid,title,fn", [(v[0], v[1], v[2]) for v in VECTORS if not v[3]])
def test_active_vector_defeated(vid, title, fn):
    status, detail = fn()
    if status is None:
        pytest.skip(f"{vid} {title}: {detail}")
    assert status is True, f"{vid} {title} BREACHED — {detail}"


@pytest.mark.xfail(strict=True, reason="residual attest->exec disk race (F5) — closes in Phase 5/8")
def test_v9_mid_session_swap_residual():
    status, detail = v9_mid_session_swap()
    # Asserts the DESIRED property (swap defeated). Fails today (xfail); when Phase 5 binds
    # execution to the attested bytes this XPASSes and strict mode turns it red, prompting
    # promotion of V9 to an active vector.
    assert status is True, f"V9 still residual — {detail}"


# --------------------------------------------------------------------------- standalone report

def _run_all():
    results = []
    for vid, title, fn, residual in VECTORS:
        try:
            status, detail = fn()
        except Exception as e:  # a crashing vector is a breach, not a pass
            status, detail = False, f"exception: {e}"
        results.append((vid, title, status, detail, residual))
    return results


def _report(as_json: bool = False) -> int:
    results = _run_all()
    active = [r for r in results if not r[4]]
    residual = [r for r in results if r[4]]
    active_defeated = sum(1 for r in active if r[2] is True)
    active_total = sum(1 for r in active if r[2] is not None)
    active_skipped = sum(1 for r in active if r[2] is None)
    residual_defeated = sum(1 for r in residual if r[2] is True)

    if as_json:
        payload = {
            "active_defeated": active_defeated,
            "active_total": active_total,
            "active_skipped": active_skipped,
            "residual_total": len(residual),
            "residual_defeated": residual_defeated,
            "robustness": f"{active_defeated}/{active_total}",
            "vectors": [
                {"id": v, "title": t,
                 "status": ("defeated" if s is True else "breached" if s is False else "skipped"),
                 "residual": r, "detail": d}
                for (v, t, s, d, r) in results
            ],
        }
        print(json.dumps(payload, indent=2))
        return 0 if active_defeated == active_total else 1

    def tag(s, r):
        if s is None:
            return "[ SKIP   ]"
        if r:
            return "[DEFEATED]" if s else "[RESIDUAL]"
        return "[DEFEATED]" if s else "[BREACHED]"

    line = "=" * 70
    print(line)
    print("  KKI Adversarial Governance Benchmark")
    print("  target: GovernedExecutor pipeline (policy -> attestation -> consent -> audit)")
    print(line)
    for vid, title, status, detail, is_residual in results:
        suffix = "  -> Phase 5/8" if (is_residual and status is not True) else ""
        print(f"  {tag(status, is_residual)} {vid}  {title:<34} {suffix}")
        print(f"             {detail}")
    print("-" * 70)
    print(f"  Robustness: {active_defeated}/{active_total} active vectors defeated"
          + (f"  ({active_skipped} skipped)" if active_skipped else "")
          + f"  ·  {len(residual) - residual_defeated} documented residual")
    ok = active_defeated == active_total
    print(f"  Result: {'PASS' if ok else 'FAIL'} (exit {0 if ok else 1})")
    print(line)
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="KKI adversarial governance benchmark")
    parser.add_argument("--report", action="store_true", help="print the human scorecard")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()
    if args.json:
        return _report(as_json=True)
    return _report(as_json=False)  # default to the report when run directly


if __name__ == "__main__":
    raise SystemExit(main())
