#!/usr/bin/env python3
"""
Per-invocation binary attestation for the KKI governance layer (IRP Task 3.1).

Before a tool runs, verify that the binary about to execute is the one we expect and
that it resolves inside a trusted system directory — defeating PATH-hijacking and
symlink-redirection where a writable directory shadows a real tool.

This is the testable, stdlib-only core of the spec's privilege-sandbox task. Full Linux
capability-namespace isolation (`unshare` / `setcap`) and a `kkid` IPC daemon are noted
as roadmap items in docs/IRP_GOVERNANCE.md.

Usage:
    from governance.attestation import attest_binary
    att = attest_binary("nmap", expected_sha256="abc123...")
    if not att.verified:
        ...   # refuse to run
"""

from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Sovereign allowlist of directories a trusted system binary may resolve into.
TRUSTED_DIRS: Tuple[str, ...] = (
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
)


@dataclass
class Attestation:
    """Result of attesting a single binary before execution."""
    name: str
    resolved_path: Optional[str]
    real_path: Optional[str]
    sha256: Optional[str]
    installed: bool
    in_trusted_dir: bool
    hash_matches: Optional[bool]   # None when no expected hash was supplied
    verified: bool                 # installed AND trusted AND (hash_matches is not False)
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _sha256(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            h = hashlib.sha256()
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _is_trusted(real_path: str) -> bool:
    rp = os.path.realpath(real_path)
    for d in TRUSTED_DIRS:
        droot = os.path.realpath(d)
        # Containment check on path components (not string prefix) to avoid /usr/bin-evil.
        try:
            if os.path.commonpath([droot, rp]) == droot:
                return True
        except ValueError:
            continue
    return False


def attest_binary(name: str, expected_sha256: Optional[str] = None) -> Attestation:
    """Attest a binary by name or absolute path.

    Resolution: if ``name`` is an absolute/relative path it is used directly; otherwise it
    is located via PATH (``shutil.which``). The path is then ``realpath``-resolved (defeats
    symlink redirection), checked for trusted-directory containment, and SHA-256 hashed.
    When ``expected_sha256`` is supplied, a mismatch flips ``verified`` to False.
    """
    if os.path.sep in name or name.startswith("."):
        resolved = name if Path(name).exists() else None
    else:
        resolved = shutil.which(name)
        if not resolved:
            for d in TRUSTED_DIRS:
                cand = os.path.join(d, name)
                if Path(cand).exists():
                    resolved = cand
                    break

    if not resolved:
        return Attestation(
            name=name, resolved_path=None, real_path=None, sha256=None,
            installed=False, in_trusted_dir=False, hash_matches=None,
            verified=False, reason="binary not found",
        )

    real_path = os.path.realpath(resolved)
    trusted = _is_trusted(real_path)
    digest = _sha256(real_path)
    hash_matches: Optional[bool] = None
    if expected_sha256 is not None:
        hash_matches = (digest is not None and digest.lower() == expected_sha256.lower())

    verified = trusted and (hash_matches is not False) and digest is not None
    if not trusted:
        reason = f"binary resolves outside trusted dirs: {real_path}"
    elif hash_matches is False:
        reason = "sha256 mismatch (possible tampering/substitution)"
    elif digest is None:
        reason = "could not hash binary"
    else:
        reason = "ok"

    return Attestation(
        name=name, resolved_path=resolved, real_path=real_path, sha256=digest,
        installed=True, in_trusted_dir=trusted, hash_matches=hash_matches,
        verified=verified, reason=reason,
    )
