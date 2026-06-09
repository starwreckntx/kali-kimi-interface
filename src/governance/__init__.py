#!/usr/bin/env python3
"""
KKI Governance Layer (IRP / MOD-045 hardening).

A stdlib-only governance stack that sits above the existing KKI execution layers and
enforces non-negotiable invariants on every proposed tool call:

  - Guardian_Codex  (policy.py)      : permission-as-code; DANGER requires consent.
  - Mirror_RTC      (consent.py)     : per-action human authorization, default-deny.
  - Mnemosyne       (audit.py)       : append-only HMAC hash-chained audit trail.
  - Loom            (validation.py,  : positive allowlist validation + per-invocation
                     attestation.py)   binary attestation (PATH/symlink hijack defense).
  - Weave           (engine.py)      : GovernedExecutor — wires the pipeline around the
                                       existing SecurityToolExecutor.

The layer is ADDITIVE: it does not remove the base adapter's DANGEROUS_CHARS blacklist or
any existing safety check; it adds stronger gates on top.
"""

from __future__ import annotations

from .validation import (
    validate_target, validate_url, validate_flags, normalize, SAFE_FLAGS, PolicyViolation,
)
from .attestation import attest_binary, Attestation, TRUSTED_DIRS
from .consent import ConsentGate, ConsentDecision, ConsentRequest, ConsentResult
from .audit import AuditLog, AuditEntry
from .policy import PolicyEngine, PolicyDecision, BlastRadius, Authorization
from .engine import GovernedExecutor, GovernedResult

__all__ = [
    "validate_target", "validate_url", "validate_flags", "normalize", "SAFE_FLAGS",
    "PolicyViolation", "attest_binary", "Attestation", "TRUSTED_DIRS",
    "ConsentGate", "ConsentDecision", "ConsentRequest", "ConsentResult",
    "AuditLog", "AuditEntry", "PolicyEngine", "PolicyDecision", "BlastRadius",
    "Authorization", "GovernedExecutor", "GovernedResult",
]
