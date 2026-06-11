#!/usr/bin/env python3
"""Ed25519 signing for the KKI governance layer (IRP Phase 7 — cryptographic root of trust).

Asymmetric signatures give the manifest and the audit log *provenance*: a verifier needs only
the public key, and a valid signature proves an offline/hardware-held private key authored the
bytes. This replaces the file-trust of F4 (a plaintext manifest an attacker with write access
could overwrite) and the session-local HMAC of the audit log (which only tamper-evidences
within one process).

Backend: the implementation is the RFC 8032 reference, pure Python over ``hashlib`` only, so
the governance core keeps its zero-dependency guarantee. If PyCA ``cryptography`` is installed
it is preferred automatically (audited C, constant-time) through the identical API — both
backends are byte-for-byte interoperable (Ed25519 is deterministic).

Caveat (stated, not buried): a hand-transcribed signature primitive is an anti-pattern. The
pure path is validated against an RFC 8032 test vector and the deterministic-signature
property; production should install ``cryptography`` to get the audited backend. The
verification path holds no secret, so pure-Python timing variance is not a verifier weakness.

API:
    seed = generate_seed()                 # 32-byte private seed
    pub  = public_key(seed)                # 32-byte public key
    sig  = sign(seed, message)             # 64-byte signature
    ok   = verify(pub, sig, message)       # bool
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Tuple

# --------------------------------------------------------------------------- RFC 8032 (pure)

_b = 256
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


def _scalarmult(P: Tuple[int, int], e: int) -> Tuple[int, int]:
    # Iterative double-and-add (avoids deep recursion for 252-bit scalars).
    result = (0, 1)
    addend = P
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y: int) -> bytes:
    return y.to_bytes(_b // 8, "little")


def _encodepoint(P: Tuple[int, int]) -> bytes:
    x, y = P
    val = (y & ((1 << (_b - 1)) - 1)) | ((x & 1) << (_b - 1))
    return val.to_bytes(_b // 8, "little")


def _decodeint(s: bytes) -> int:
    return int.from_bytes(s, "little")


def _isoncurve(P: Tuple[int, int]) -> bool:
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodepoint(s: bytes) -> Tuple[int, int]:
    y = int.from_bytes(s, "little") & ((1 << (_b - 1)) - 1)
    x = _xrecover(y)
    if (x & 1) != _bit(s, _b - 1):
        x = _q - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("decoded point is not on the curve")
    return P


def _secret_scalar(h: bytes) -> int:
    return 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))


def _pure_public_key(seed: bytes) -> bytes:
    h = _H(seed)
    a = _secret_scalar(h)
    return _encodepoint(_scalarmult(_B, a))


def _pure_sign(seed: bytes, msg: bytes) -> bytes:
    h = _H(seed)
    a = _secret_scalar(h)
    pub = _encodepoint(_scalarmult(_B, a))
    r = _decodeint(_H(h[_b // 8:_b // 4] + msg)) % _L
    R = _encodepoint(_scalarmult(_B, r))
    k = _decodeint(_H(R + pub + msg)) % _L
    S = (r + k * a) % _L
    return R + _encodeint(S)


def _pure_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pub)
    except (ValueError, Exception):
        return False
    S = _decodeint(sig[32:])
    if S >= _L:
        return False
    k = _decodeint(_H(sig[:32] + pub + msg)) % _L
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, k))


# --------------------------------------------------------------------------- optional PyCA

def _try_pyca():
    """Import + smoke-test PyCA Ed25519, suppressing the OS-level rust panic a broken install
    emits to fd 2. Returns the primitives on success, else None (use the pure backend)."""
    import os
    devnull = os.open(os.devnull, os.O_WRONLY)
    saved = os.dup(2)
    os.dup2(devnull, 2)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey as _Priv, Ed25519PublicKey as _Pub,
        )
        from cryptography.exceptions import InvalidSignature as _Inv
        _k = _Priv.generate()
        _k.public_key().public_bytes_raw()          # actually exercise the backend
        return _Priv, _Pub, _Inv
    except BaseException:
        return None
    finally:
        os.dup2(saved, 2)
        os.close(saved)
        os.close(devnull)


_pyca = _try_pyca()
_HAVE_PYCA = _pyca is not None
if _HAVE_PYCA:
    Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature = _pyca

BACKEND = "pyca" if _HAVE_PYCA else "pure"


def generate_seed() -> bytes:
    """A 32-byte private seed from the OS CSPRNG."""
    return secrets.token_bytes(32)


def public_key(seed: bytes) -> bytes:
    if _HAVE_PYCA:
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    return _pure_public_key(seed)


def sign(seed: bytes, msg: bytes) -> bytes:
    if _HAVE_PYCA:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    return _pure_sign(seed, msg)


def verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    if _HAVE_PYCA:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except (InvalidSignature, Exception):
            return False
    return _pure_verify(pub, sig, msg)


# --------------------------------------------------------------------------- hex helpers

def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s.strip())


# --------------------------------------------------------------------------- detached signatures

import json
from pathlib import Path

SIG_SUFFIX = ".sig"


class SignatureError(Exception):
    """Raised on a verification failure that must halt execution (no TOFU fallback)."""


def resolve_pubkey(pubkey) -> bytes:
    """Accept a 64-hex string, raw 32 bytes, or a path to a file containing the hex key."""
    if isinstance(pubkey, (bytes, bytearray)):
        return bytes(pubkey)
    s = str(pubkey).strip()
    if len(s) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in s):
        return from_hex(s)
    return from_hex(Path(s).read_text().strip())


resolve_seed = resolve_pubkey   # a private seed is also a 32-byte hex value / file


def sign_detached(payload: bytes, seed: bytes) -> dict:
    return {"algorithm": "ed25519", "signature": sign(seed, payload).hex(),
            "public_key": public_key(seed).hex()}


def verify_detached(payload: bytes, sig_obj: dict, trusted_pubkey: bytes) -> bool:
    if not isinstance(sig_obj, dict) or sig_obj.get("algorithm") != "ed25519":
        return False
    try:
        return verify(trusted_pubkey, from_hex(sig_obj.get("signature", "")), payload)
    except (ValueError, TypeError):
        return False


def write_signature(path, seed) -> str:
    """Write a detached <path>.sig for the file at ``path``; returns the .sig path."""
    payload = Path(path).read_bytes()
    sig_path = str(path) + SIG_SUFFIX
    Path(sig_path).write_text(json.dumps(sign_detached(payload, seed), indent=2))
    return sig_path


def verify_file_signature(path, trusted_pubkey: bytes) -> Tuple[bool, str]:
    """Verify <path>.sig against the file bytes using the operator-supplied trusted key.

    The trusted key always wins — a key embedded in the .sig is informational only, never
    trusted, so an attacker cannot re-sign with their own key and have it accepted.
    """
    sig_path = str(path) + SIG_SUFFIX
    if not Path(sig_path).exists():
        return False, "no detached signature (.sig) present"
    try:
        sig_obj = json.loads(Path(sig_path).read_text())
    except (OSError, ValueError) as e:
        return False, f"unreadable signature: {e}"
    payload = Path(path).read_bytes()
    ok = verify_detached(payload, sig_obj, trusted_pubkey)
    return ok, ("ok" if ok else "signature verification failed against supplied public key")

