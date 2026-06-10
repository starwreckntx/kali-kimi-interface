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

import contextlib
import hashlib
import os
import shutil
import subprocess
from contextvars import ContextVar
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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


# ---------------------------------------------------------------------------------------------
# File-descriptor pinning (closes the attest->exec TOCTOU disk race, audit finding F5).
#
# `attest_binary` hashes a path; between that hash and the eventual execve the file could be
# swapped. Pinning holds an O_RDONLY fd open from attestation time and executes THAT inode via
# /proc/self/fd/<fd> (Linux has no os.fexecve), so the bytes hashed are the bytes executed:
#   - replace-by-rename  -> the fd still anchors the original inode (path swap is irrelevant)
#   - in-place rewrite   -> recheck() re-hashes the fd and catches the changed bytes
# The fd MUST be released on every exit path (deny / timeout / recheck-fail / exception /
# crash-unwind); `pin_binary` is a context manager whose finally clause guarantees that —
# never relying on garbage collection.
# ---------------------------------------------------------------------------------------------

PROCFS_FD_AVAILABLE: bool = os.path.isdir("/proc/self/fd")


def _hash_fd(fd: int) -> Optional[str]:
    """SHA-256 the whole file behind ``fd`` via offset reads (does not disturb the offset)."""
    try:
        h = hashlib.sha256()
        offset = 0
        while True:
            chunk = os.pread(fd, 65536, offset)
            if not chunk:
                break
            h.update(chunk)
            offset += len(chunk)
        return h.hexdigest()
    except OSError:
        return None


@dataclass
class PinnedBinary:
    """A binary pinned by an open fd for the lifetime of one governed execution.

    Use only via :func:`pin_binary` so the fd is closed deterministically. ``fd`` is None when
    the binary is unpinnable (not verified, or no procfs) — callers must fail closed for
    enforced tiers.
    """
    attestation: Attestation
    fd: Optional[int]

    @property
    def sha256(self) -> Optional[str]:
        return self.attestation.sha256

    @property
    def pinned(self) -> bool:
        return self.fd is not None

    def recheck(self) -> bool:
        """Re-hash through the pinned fd; True iff it still equals the attested hash.

        Catches an in-place rewrite of the same inode during the gate/consent wait.
        """
        if self.fd is None or self.attestation.sha256 is None:
            return False
        current = _hash_fd(self.fd)
        return current is not None and current == self.attestation.sha256

    def run(self, argv: List[str], **kwargs: Any) -> "subprocess.CompletedProcess":
        """subprocess.run the PINNED inode (no path re-resolution), preserving argv + kwargs."""
        if self.fd is None:
            raise RuntimeError("PinnedBinary.run called without a pinned fd")
        pass_fds = tuple(set(kwargs.pop("pass_fds", ())) | {self.fd})
        return subprocess.run(argv, executable=f"/proc/self/fd/{self.fd}",
                              pass_fds=pass_fds, **kwargs)

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            finally:
                self.fd = None


@contextlib.contextmanager
def pin_binary(name: str, expected_sha256: Optional[str] = None):
    """Attest ``name``, pin its inode with an O_RDONLY fd, and yield a :class:`PinnedBinary`.

    The fd is ALWAYS closed on exit — normal return, denial, timeout, recheck failure, or an
    exception propagating out of the ``with`` block. On a non-procfs platform (or if the open
    fails, or the binary did not verify) ``fd`` is None and the caller fails closed.
    """
    att = attest_binary(name, expected_sha256=expected_sha256)
    fd: Optional[int] = None
    if att.verified and att.real_path and PROCFS_FD_AVAILABLE:
        try:
            fd = os.open(att.real_path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            # Anchor check: the through-fd hash must equal the path hash attestation computed,
            # otherwise the file changed between the two opens — refuse to pin.
            if _hash_fd(fd) != att.sha256:
                os.close(fd)
                fd = None
        except OSError:
            fd = None
    pinned = PinnedBinary(att, fd)
    try:
        yield pinned
    finally:
        pinned.close()


# The active pin for the current execution context. The engine sets it around dispatch so the
# L2 adapter can exec the pinned inode without changing the generic execute(tool, params) ABI.
_active_pin: "ContextVar[Optional[PinnedBinary]]" = ContextVar("kki_active_pin", default=None)


@contextlib.contextmanager
def active_pin(pinned: Optional[PinnedBinary]):
    token = _active_pin.set(pinned)
    try:
        yield
    finally:
        _active_pin.reset(token)


def get_active_pin() -> Optional[PinnedBinary]:
    return _active_pin.get()
