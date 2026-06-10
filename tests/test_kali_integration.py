"""Real-Kali integration checks for the governance stack.

These exercise the seam between *tested logic* and *live binaries*. Tests that need a real
tool self-skip when the binary is absent (mirroring tests/test_kali_tools.py), so the suite
stays green in a bare container and becomes meaningful on a Kali host.

Encodes the five operational acceptance checks:
  1. attest_binary("nmap") SHA-256 matches `sha256sum /usr/bin/nmap`   (skips w/o nmap)
  2. masscan rate cap rejects >100000 pps before any subprocess
  3. tshark interface allowlist blocks docker0
  4. consent denial => zero base-executor calls (core invariant)
  5. governed nmap on localhost runs after APPROVE, audit verifies, tamper is caught (skips w/o nmap)

Run on a Kali box:
    python3 -m pytest tests/test_kali_integration.py -v
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "src"))

from kali_tools import KaliToolAdapter, SecurityToolError
from harness_integration import SecurityToolExecutor
from governance.engine import GovernedExecutor
from governance.policy import PolicyEngine
from governance.consent import ConsentGate
from governance.audit import AuditLog
from governance.attestation import attest_binary

NMAP = Path("/usr/bin/nmap")


# 1 ── attestation against the real binary --------------------------------------------------
@pytest.mark.skipif(not NMAP.exists(), reason="nmap not installed")
def test_attest_real_nmap_matches_sha256sum():
    att = attest_binary("nmap")
    assert att.installed and att.in_trusted_dir and att.verified
    assert att.sha256 and len(att.sha256) == 64
    on_disk = hashlib.sha256(Path(att.real_path).read_bytes()).hexdigest()
    assert att.sha256 == on_disk, "attestation hash diverged from on-disk binary"


# 2 ── masscan rate ceiling (rejected before any subprocess) --------------------------------
def test_masscan_rate_cap_before_subprocess():
    with pytest.raises(SecurityToolError) as exc:
        KaliToolAdapter().masscan_scan("127.0.0.1", rate=200000)
    assert "exceeds MAX_MASSCAN_RATE" in str(exc.value)


# 3 ── tshark interface allowlist -----------------------------------------------------------
def test_tshark_allowlist_blocks_docker0():
    with pytest.raises(SecurityToolError) as exc:
        KaliToolAdapter().tshark_capture(interface="docker0")
    assert "not in allowed set" in str(exc.value)


# helpers -----------------------------------------------------------------------------------
def _deny_gate() -> ConsentGate:
    # No response from the operator -> default-deny.
    return ConsentGate(prompt_fn=lambda req, timeout: None)


def _approve_gate() -> ConsentGate:
    return ConsentGate(prompt_fn=lambda req, timeout: f"APPROVE {req.nonce}")


def _governed(consent: ConsentGate):
    base = SecurityToolExecutor()
    gov = GovernedExecutor(executor=base, policy=PolicyEngine(), consent=consent,
                           audit=AuditLog(session_id="itest"))
    return base, gov


# 4 ── core invariant: denial => zero base-executor calls -----------------------------------
def test_consent_denial_zero_base_calls():
    base, gov = _governed(_deny_gate())
    calls = {"n": 0}
    original = base.execute

    def spy(name, params):
        calls["n"] += 1
        return original(name, params)

    base.execute = spy  # GovernedExecutor holds `base` and dispatches at call time
    gr = gov.execute("nmap_scan", {"target": "127.0.0.1"})
    # Blocked at consent (nmap present) or attestation (nmap absent) — either way the base
    # executor must never be reached.
    assert gr.allowed is False
    assert calls["n"] == 0


# 5 ── end-to-end governed nmap + audit verify/tamper ---------------------------------------
@pytest.mark.skipif(not NMAP.exists(), reason="nmap not installed")
def test_governed_nmap_localhost_with_approval_and_audit(tmp_path):
    base, gov = _governed(_approve_gate())
    gr = gov.execute("nmap_scan", {"target": "127.0.0.1", "ports": "22,80"})
    assert gr.allowed is True
    assert gr.result is not None

    ok, first_bad = gov.audit.verify()
    assert ok and first_bad is None

    chain = gov.audit.save(str(tmp_path / "session.chain"))
    okf, _, reason = AuditLog.verify_file(chain)
    assert okf and reason == "ok"

    # Flip a payload in the persisted chain and confirm read-back catches it.
    data = json.loads(Path(chain).read_text())
    data["entries"][0]["payload"] = {"tampered": True}
    Path(chain).write_text(json.dumps(data))
    okf2, seq2, reason2 = AuditLog.verify_file(chain)
    assert okf2 is False and seq2 == 0 and reason2 in ("hash_mismatch", "chain_break")
