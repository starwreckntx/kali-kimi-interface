"""Phase 7 — Ed25519 cryptographic root of trust.

Covers the signing primitive (self-consistency + RFC-conformance via PyCA interop where
available), detached manifest signatures, the registry CRITICAL_HALT on a bad/missing
signature, and Ed25519 chain-signing of the audit log.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "src"))

from governance import crypto
from governance.audit import AuditLog
from tool_registry import VerifiableToolRegistry


# --------------------------------------------------------------------------- primitive

class TestEd25519Primitive:
    def test_roundtrip(self):
        seed = crypto.generate_seed()
        pub = crypto.public_key(seed)
        sig = crypto.sign(seed, b"payload")
        assert len(seed) == 32 and len(pub) == 32 and len(sig) == 64
        assert crypto.verify(pub, sig, b"payload") is True

    def test_deterministic_signature(self):
        # Ed25519 is deterministic — a random-nonce scheme would fail this.
        seed = crypto.generate_seed()
        assert crypto.sign(seed, b"abc") == crypto.sign(seed, b"abc")

    def test_tamper_and_wrong_key_rejected(self):
        seed = crypto.generate_seed()
        pub = crypto.public_key(seed)
        sig = crypto.sign(seed, b"abc")
        assert crypto.verify(pub, sig, b"abd") is False
        assert crypto.verify(crypto.public_key(crypto.generate_seed()), sig, b"abc") is False
        assert crypto.verify(pub, b"\x00" * 64, b"abc") is False

    @pytest.mark.skipif(crypto.BACKEND != "pyca",
                        reason="PyCA cryptography not available — RFC-conformance interop skipped")
    def test_pyca_interop_is_byte_identical(self):
        # When PyCA is present, the pure and PyCA backends are byte-for-byte interoperable,
        # which proves RFC 8032 conformance against an audited reference.
        seed = crypto.generate_seed()
        assert crypto._pure_public_key(seed) == crypto.public_key(seed)
        assert crypto._pure_sign(seed, b"x") == crypto.sign(seed, b"x")
        assert crypto.verify(crypto._pure_public_key(seed), crypto._pure_sign(seed, b"x"), b"x")


# --------------------------------------------------------------------------- detached manifest sig

class TestManifestSignature:
    def _signed_manifest(self, d):
        mp = os.path.join(d, "m.json")
        Path(mp).write_text(json.dumps({"fingerprints": {"/usr/bin/x": "ab" * 32}}))
        seed = crypto.generate_seed()
        crypto.write_signature(mp, seed)
        return mp, crypto.public_key(seed)

    def test_valid_signature_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            mp, pub = self._signed_manifest(d)
            ok, reason = crypto.verify_file_signature(mp, pub)
            assert ok is True and reason == "ok"

    def test_tampered_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            mp, pub = self._signed_manifest(d)
            Path(mp).write_text(Path(mp).read_text() + " ")
            ok, _ = crypto.verify_file_signature(mp, pub)
            assert ok is False

    def test_wrong_pubkey_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            mp, _ = self._signed_manifest(d)
            other = crypto.public_key(crypto.generate_seed())
            ok, _ = crypto.verify_file_signature(mp, other)
            assert ok is False


# --------------------------------------------------------------------------- registry CRITICAL_HALT

class TestRegistrySignatureHalt:
    def test_signed_manifest_loads(self):
        with tempfile.TemporaryDirectory() as d:
            mp = os.path.join(d, "m.json")
            VerifiableToolRegistry().save_manifest(mp)
            seed = crypto.generate_seed()
            crypto.write_signature(mp, seed)
            reg = VerifiableToolRegistry(manifest=mp, pubkey=crypto.public_key(seed).hex())
            assert reg.signature_status == "verified" and reg.manifest_mode is True

    def test_forged_manifest_halts(self):
        with tempfile.TemporaryDirectory() as d:
            mp = os.path.join(d, "m.json")
            VerifiableToolRegistry().save_manifest(mp)
            seed = crypto.generate_seed()
            crypto.write_signature(mp, seed)
            Path(mp).write_text(json.dumps({"fingerprints": {"/usr/bin/x": "00" * 32}}))  # re-write, no re-sign
            with pytest.raises(crypto.SignatureError):
                VerifiableToolRegistry(manifest=mp, pubkey=crypto.public_key(seed).hex())

    def test_missing_signature_with_pubkey_halts(self):
        with tempfile.TemporaryDirectory() as d:
            mp = os.path.join(d, "m.json")
            VerifiableToolRegistry().save_manifest(mp)        # no .sig written
            with pytest.raises(crypto.SignatureError):
                VerifiableToolRegistry(manifest=mp, pubkey=crypto.public_key(crypto.generate_seed()).hex())


# --------------------------------------------------------------------------- audit Ed25519 signing

class TestAuditEd25519:
    def _signed_chain(self, d, seed):
        log = AuditLog(session_id="s", signing_key=seed)
        for i in range(4):
            log.append("decision", {"i": i})
        return log.save(os.path.join(d, "a.chain"))

    def test_chain_signature_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            seed = crypto.generate_seed()
            path = self._signed_chain(d, seed)
            ok, bad, reason = AuditLog.verify_file(path, public_key=crypto.public_key(seed))
            assert ok is True and bad is None and reason == "ok"

    def test_tamper_caught_by_chain_before_signature(self):
        with tempfile.TemporaryDirectory() as d:
            seed = crypto.generate_seed()
            path = self._signed_chain(d, seed)
            data = json.loads(Path(path).read_text())
            data["entries"][2]["payload"]["i"] = 999
            Path(path).write_text(json.dumps(data))
            ok, bad, reason = AuditLog.verify_file(path, public_key=crypto.public_key(seed))
            assert ok is False and bad == 2

    def test_wrong_pubkey_signature_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            seed = crypto.generate_seed()
            path = self._signed_chain(d, seed)
            ok, bad, reason = AuditLog.verify_file(path, public_key=crypto.public_key(crypto.generate_seed()))
            assert ok is False and reason == "signature_mismatch"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
