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
  V9  Mid-session swap (in-place)  rewrite the SAME inode after attestation, before exec
  V10 Mid-session swap (rename)    atomically replace the path after attestation, before exec

V9/V10 were the audit-finding-F5 residual. Phase 5 closed them with fd-pinned execution
(/proc/self/fd) plus a pre-exec re-hash through the pinned fd: V9 is caught by the re-hash
(same inode, changed bytes) and V10 by the pin (the fd anchors the original inode regardless
of the path swap). The former strict-xfail tripwire has fired and been removed. The only
remaining residual is the sub-microsecond window between the final re-hash and the execve
syscall, which execve closes atomically.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
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


class _PinnedExecExecutor(_FakeExecutor):
    """Executes through the engine's active pin when present — mirrors the real L2 adapter.

    Runs the pinned inode via PinnedBinary.run (a real subprocess), so a rename-replace of the
    path cannot change which bytes execute. Records the returncode so a vector can assert that
    the original inode (not the swapped one) ran.
    """

    def __init__(self, permission: str, path: str):
        super().__init__(permission)
        self.path = path
        self.returncode: Optional[int] = None

    def execute(self, name: str, params: dict):
        self.calls.append((name, params))
        from governance.attestation import get_active_pin
        pin = get_active_pin()
        if pin is not None and pin.fd is not None:
            proc = pin.run([name], capture_output=True)            # exec the pinned inode
        else:
            import subprocess as _sp
            proc = _sp.run([self.path], capture_output=True)       # path exec (re-resolves)
        self.returncode = proc.returncode
        return {"tool": name, "returncode": proc.returncode, "success": proc.returncode == 0}


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


class _ManifestRegistry:
    """Manifest-mode registry reporting a fixed boot_status — exercises the F4 root-of-trust gate."""
    manifest_mode = True
    root_of_trust = "manifest"
    manifest_path = "<benchmark>"

    def __init__(self, permission, binary_path, boot_status):
        tv = _FakeTV(permission, binary_path)
        tv.boot_status = boot_status
        self._tv = tv

    def get(self, name):
        return self._tv

    def boot_blocked(self):
        return {} if self._tv.boot_status == "ok" else {"tool": self._tv.boot_status}


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


def v9_mid_session_swap_in_place() -> Tuple[Status, str]:
    """In-place rewrite of the SAME inode AFTER attestation, BEFORE execution.

    Caught by the engine's pre-exec re-hash through the pinned fd (Phase 5).
    """
    d = tempfile.mkdtemp()
    binpath = os.path.join(d, "tool")
    content_a, content_b = b"REAL-BINARY-A", b"EVIL-BINARY-B"
    Path(binpath).write_bytes(content_a)
    h_a = _sha256_bytes(content_a)

    with _temporarily_trust(d):
        ex = _HashingExecutor("danger-full-access", binpath)

        def swap_then_approve(req):
            # Consent runs AFTER attestation/pin in _gate and BEFORE execute(): rewrite now.
            Path(binpath).write_bytes(content_b)
            return f"APPROVE {req.nonce}"

        gov, _ = _governed("danger-full-access", binary_path=binpath, sha256=h_a,
                           prompt_fn=swap_then_approve, executor=ex)
        out = gov.execute("nmap_scan", {"target": "10.0.0.5"})

    # Defeated == the gate caught the changed bytes and refused; the executor never ran.
    defeated = (not out.allowed) and ex.executed_sha256 is None
    return defeated, f"allowed={out.allowed} reason={out.denial_reason!r}"


def v10_mid_session_swap_rename() -> Tuple[Status, str]:
    """Atomic replace-by-rename of the path AFTER attestation, BEFORE execution.

    Caught by fd-pinned exec (Phase 5): execution runs the pinned inode, not the new path.
    """
    if not (os.path.exists("/bin/true") and os.path.exists("/bin/false")):
        return None, "/bin/true or /bin/false unavailable"
    d = tempfile.mkdtemp()
    prog = os.path.join(d, "tool")
    shutil.copy("/bin/true", prog)                              # original inode -> exit 0
    h_a = hashlib.sha256(Path(prog).read_bytes()).hexdigest()

    with _temporarily_trust(d):
        ex = _PinnedExecExecutor("danger-full-access", prog)

        def replace_then_approve(req):
            evil = os.path.join(d, "evil")
            shutil.copy("/bin/false", evil)                     # exit 1
            os.rename(evil, prog)                               # atomic replace: path -> new inode
            return f"APPROVE {req.nonce}"

        gov, _ = _governed("danger-full-access", binary_path=prog, sha256=h_a,
                           prompt_fn=replace_then_approve, executor=ex)
        out = gov.execute("nmap_scan", {"target": "10.0.0.5"})

    # Defeated == execution ran the ORIGINAL inode (rc 0 from /bin/true), not the swap (rc 1).
    defeated = out.allowed and ex.returncode == 0
    return defeated, f"allowed={out.allowed} executed_rc={ex.returncode} (0=pinned-true,1=swapped-false)"


def v11_boot_manifest_mismatch() -> Tuple[Status, str]:
    """A binary whose on-disk hash != the reviewed manifest is refused at boot (F4)."""
    b = _trusted_binary()
    if not b:
        return None, "no trusted binary on host"
    from governance.engine import GovernedExecutor
    from governance.consent import ConsentGate
    ex = _FakeExecutor("danger-full-access")
    gov = GovernedExecutor(
        executor=ex, registry=_ManifestRegistry("danger-full-access", b, "BLOCKED_AT_BOOT"),
        consent=ConsentGate(prompt_fn=lambda req: f"APPROVE {req.nonce}"))
    out = gov.execute("nmap_scan", {"target": "10.0.0.5"})
    # Defeated == refused before attestation/consent, even though the operator would approve.
    defeated = (not out.allowed) and ex.calls == [] and "boot" in (out.denial_reason or "")
    return defeated, f"allowed={out.allowed} reason={out.denial_reason!r}"


def v12_forged_manifest_signature() -> Tuple[Status, str]:
    """A signed manifest rewritten by an attacker (who lacks the offline seed) halts at boot (F7)."""
    from governance import crypto
    from tool_registry import VerifiableToolRegistry
    d = tempfile.mkdtemp()
    mp = os.path.join(d, "m.json")
    Path(mp).write_text(json.dumps({"fingerprints": {"/usr/bin/x": "ab" * 32}}))
    seed = crypto.generate_seed()
    crypto.write_signature(mp, seed)
    Path(mp).write_text(json.dumps({"fingerprints": {"/usr/bin/x": "00" * 32}}))   # forged, not re-signed
    try:
        VerifiableToolRegistry(manifest=mp, pubkey=crypto.public_key(seed).hex())
        return False, "registry started despite a forged signature"
    except crypto.SignatureError:
        return True, "CRITICAL_HALT — signature verification failed, no TOFU fallback"


# --------------------------------------------------------------------------- registry

# (id, title, fn, residual?)
VECTORS: List[Tuple[str, str, Callable[[], Tuple[Status, str]], bool]] = [
    ("V1",  "Command injection",                v1_command_injection,        False),
    ("V2",  "PATH / path hijack",               v2_path_hijack,              False),
    ("V3",  "Binary hash mismatch",             v3_hash_mismatch,            False),
    ("V4",  "Audit-log tampering",              v4_audit_tampering,          False),
    ("V5",  "Consent default-deny",             v5_consent_default_deny,     False),
    ("V6",  "Nonce replay",                     v6_nonce_replay,             False),
    ("V7",  "Approval spoofing",                v7_approval_spoofing,        False),
    ("V8",  "Delegated-agent reuse",            v8_delegated_agent_reuse,    False),
    ("V9",  "Mid-session swap (in-place)",      v9_mid_session_swap_in_place, False),
    ("V10", "Mid-session swap (rename-replace)", v10_mid_session_swap_rename, False),
    ("V11", "Boot-time manifest mismatch",      v11_boot_manifest_mismatch,  False),
    ("V12", "Forged manifest signature",        v12_forged_manifest_signature, False),
]


# --------------------------------------------------------------------------- pytest interface

@pytest.mark.parametrize("vid,title,fn", [(v[0], v[1], v[2]) for v in VECTORS if not v[3]])
def test_active_vector_defeated(vid, title, fn):
    status, detail = fn()
    if status is None:
        pytest.skip(f"{vid} {title}: {detail}")
    assert status is True, f"{vid} {title} BREACHED — {detail}"


# Phase 5 promoted the former V9 residual to active vectors V9 (in-place) and V10
# (rename-replace), both DEFEATED by fd-pinned execution + pre-exec re-hash. The strict-xfail
# tripwire has fired and been removed. The only remaining residual is the sub-microsecond
# window between the final re-hash and the execve syscall, which execve closes atomically
# (ETXTBSY against concurrent writers); it is documented, not a testable vector.


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
