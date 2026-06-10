#!/usr/bin/env python3
"""
Append-only, hash-chained audit log for the KKI governance layer (Mnemosyne / IRP 4.1).

Each entry is linked to its predecessor by a SHA-256 chain and tamper-evidenced with an
HMAC-SHA256 keyed tag, giving a non-repudiable-within-trust-boundary trail. The log
carries a self-referential AUDITOR STATE (a hash over the whole chain) so the trail can
attest to its own integrity.

Stdlib-only by design. The spec's Ed25519 + hardware-backed key is a documented upgrade
path; HMAC gives tamper-evidence wherever the key is held securely. Swap `key` for a
persisted/HSM-held secret to extend the trust boundary.

Usage:
    from governance.audit import AuditLog
    log = AuditLog()
    log.log_decision({"tool": "nmap_scan", "authorization": "REQUIRES_CONSENT"})
    log.log_execution({"tool": "nmap", "returncode": 0})
    ok, bad = log.verify()
    log.save("results/audit-<session>.json")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    seq: int
    timestamp: str
    category: str           # "decision" | "execution" | "integrity"
    payload: Dict[str, Any]
    prev_hash: str
    entry_hash: str
    hmac: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AuditLog:
    """Append-only hash-chained, HMAC-tagged audit trail."""

    def __init__(self, key: Optional[bytes] = None, session_id: Optional[str] = None):
        # An ephemeral key still tamper-evidences the trail for the life of the process
        # and any consumer that trusts this run. Persist/inject a key for cross-run
        # non-repudiation.
        self.key = key if key is not None else secrets.token_bytes(32)
        self.session_id = session_id or f"kki-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self._entries: List[AuditEntry] = []

    @property
    def entries(self) -> List[AuditEntry]:
        return list(self._entries)

    def _head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def append(self, category: str, payload: Dict[str, Any]) -> AuditEntry:
        seq = len(self._entries)
        prev_hash = self._head_hash()
        timestamp = datetime.now().isoformat()
        body = {
            "seq": seq,
            "timestamp": timestamp,
            "category": category,
            "payload": payload,
            "prev_hash": prev_hash,
        }
        entry_hash = hashlib.sha256(_canonical(body)).hexdigest()
        tag = hmac.new(self.key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        entry = AuditEntry(
            seq=seq, timestamp=timestamp, category=category, payload=payload,
            prev_hash=prev_hash, entry_hash=entry_hash, hmac=tag,
        )
        self._entries.append(entry)
        return entry

    # Convenience wrappers for the three IRP log streams (one chain, category-tagged).
    def log_decision(self, payload: Dict[str, Any]) -> AuditEntry:
        return self.append("decision", payload)

    def log_execution(self, payload: Dict[str, Any]) -> AuditEntry:
        return self.append("execution", payload)

    def log_integrity(self, payload: Dict[str, Any]) -> AuditEntry:
        return self.append("integrity", payload)

    def verify(self) -> Tuple[bool, Optional[int]]:
        """Re-walk the chain; return (ok, first_bad_seq). first_bad_seq is None when ok."""
        prev_hash = GENESIS_HASH
        for entry in self._entries:
            body = {
                "seq": entry.seq,
                "timestamp": entry.timestamp,
                "category": entry.category,
                "payload": entry.payload,
                "prev_hash": entry.prev_hash,
            }
            recomputed = hashlib.sha256(_canonical(body)).hexdigest()
            if entry.prev_hash != prev_hash or recomputed != entry.entry_hash:
                return False, entry.seq
            expected_tag = hmac.new(
                self.key, entry.entry_hash.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(expected_tag, entry.hmac):
                return False, entry.seq
            prev_hash = entry.entry_hash
        return True, None

    @staticmethod
    def verify_file(path: str, key: Optional[bytes] = None) -> Tuple[bool, Optional[int], str]:
        """Read back a saved chain file and verify its integrity.

        Re-walks the SHA-256 hash chain (recomputing each entry_hash from its body and
        checking prev_hash linkage) — this is keyless and detects any payload tampering or
        reordering. If ``key`` is supplied, the HMAC tag is also checked. The on-disk format
        deliberately omits the key, so cross-process HMAC verification requires injecting
        the same key used to write the chain (see the Ed25519/HSM upgrade path).

        Returns (ok, first_bad_seq, reason). first_bad_seq is None when ok.
        """
        with open(path) as f:
            data = json.load(f)
        entries = data.get("entries", [])
        prev_hash = GENESIS_HASH
        for entry in entries:
            body = {
                "seq": entry["seq"],
                "timestamp": entry["timestamp"],
                "category": entry["category"],
                "payload": entry["payload"],
                "prev_hash": entry["prev_hash"],
            }
            recomputed = hashlib.sha256(_canonical(body)).hexdigest()
            if entry["prev_hash"] != prev_hash:
                return False, entry["seq"], "chain_break"
            if recomputed != entry["entry_hash"]:
                return False, entry["seq"], "hash_mismatch"
            if key is not None:
                expected = hmac.new(key, entry["entry_hash"].encode("utf-8"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, entry["hmac"]):
                    return False, entry["seq"], "hmac_mismatch"
            prev_hash = entry["entry_hash"]
        return True, None, "ok"

    def auditor_state(self) -> Dict[str, Any]:
        """Self-referential state: a hash over every entry hash plus head and count."""
        digest = hashlib.sha256(
            _canonical([e.entry_hash for e in self._entries])
        ).hexdigest()
        ok, bad = self.verify()
        return {
            "session_id": self.session_id,
            "entry_count": len(self._entries),
            "head_hash": self._head_hash(),
            "chain_digest": digest,
            "chain_valid": ok,
            "first_bad_seq": bad,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "auditor_state": self.auditor_state(),
            "entries": [e.to_dict() for e in self._entries],
        }

    def save(self, path: str) -> str:
        import os
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path
