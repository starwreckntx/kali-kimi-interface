#!/usr/bin/env python3
"""
Guardian_Codex — permission-as-code policy engine for the KKI governance layer
(IRP Tasks 3.7 / 3.8). Permission is a *function of context*, not a static enum read.

The policy engine is the apex: it consumes a tool's declared blast radius plus the
proposed parameters and returns an Authorization. Crucially, `DANGER` actions return
REQUIRES_CONSENT — they cannot be GRANTED by policy alone; only the Mirror_RTC human gate
can clear them. The LLM never sees this code path and cannot reason around it.

Usage:
    from governance.policy import PolicyEngine
    engine = PolicyEngine(network_scope=["10.0.0.0/8"])
    decision = engine.evaluate("nmap_scan", "danger-full-access", {"target": "10.0.0.5"})
    decision.authorization   # Authorization.REQUIRES_CONSENT
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    from .validation import validate_target, validate_url, validate_flags, PolicyViolation
except ImportError:  # direct execution / flat sys.path
    from validation import validate_target, validate_url, validate_flags, PolicyViolation


class BlastRadius(Enum):
    """Cost/impact classification, derived from the tool's required permission."""
    RECON = "recon"     # read-only
    WRITE = "write"     # workspace-write
    DANGER = "danger"   # danger-full-access

    @classmethod
    def from_permission(cls, permission: str) -> "BlastRadius":
        mapping = {
            "read-only": cls.RECON,
            "workspace-write": cls.WRITE,
            "danger-full-access": cls.DANGER,
        }
        if permission not in mapping:
            # Unknown permission is treated as maximally dangerous (fail closed).
            return cls.DANGER
        return mapping[permission]


class Authorization(Enum):
    GRANTED = "granted"
    DENIED = "denied"
    REQUIRES_CONSENT = "requires_consent"


# Parameter fields that carry a target/url/flags and must be allowlist-validated.
_TARGET_FIELDS = ("target", "host")
_URL_FIELDS = ("url",)
_FLAG_FIELDS = ("flags",)


@dataclass
class PolicyDecision:
    tool: str
    blast_radius: BlastRadius
    authorization: Authorization
    reasons: List[str] = field(default_factory=list)
    normalized_params: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "blast_radius": self.blast_radius.value,
            "authorization": self.authorization.value,
            "reasons": self.reasons,
            "normalized_params": self.normalized_params,
        }


class PolicyEngine:
    """Evaluates whether a proposed tool call may proceed, and at what gate."""

    def __init__(self, network_scope: Optional[List[str]] = None, tool_to_binary: Optional[Dict[str, str]] = None):
        # NETWORK_SCOPE_ALLOWLIST (AG-01). None => scope check skipped (flagged in reasons).
        self.network_scope = network_scope
        # Maps harness tool names (e.g. "nmap_scan") to binary names (e.g. "nmap") so the
        # right SAFE_FLAGS allowlist is selected.
        self.tool_to_binary = tool_to_binary or {
            "nmap_scan": "nmap", "masscan_quick": "masscan", "gobuster_scan": "gobuster",
            "dirb_scan": "dirb", "nikto_scan": "nikto", "hydra_scan": "hydra",
            "sqlmap_scan": "sqlmap", "quick_recon": "nmap",
        }

    def evaluate(self, tool_name: str, permission: str, params: Dict[str, Any]) -> PolicyDecision:
        blast = BlastRadius.from_permission(permission)
        reasons: List[str] = []
        normalized: Dict[str, Any] = {}

        # 1. Positive validation of every parameter that reaches a command line.
        try:
            for fld in _TARGET_FIELDS:
                if fld in params and params[fld]:
                    normalized[fld] = validate_target(str(params[fld]), scope=self.network_scope)
            for fld in _URL_FIELDS:
                if fld in params and params[fld]:
                    normalized[fld] = validate_url(str(params[fld]), scope=self.network_scope)
            binary = self.tool_to_binary.get(tool_name, tool_name)
            for fld in _FLAG_FIELDS:
                if fld in params and params[fld]:
                    normalized[fld] = validate_flags(binary, str(params[fld]))
        except PolicyViolation as e:
            reasons.append(f"policy_violation: {e}")
            return PolicyDecision(tool_name, blast, Authorization.DENIED, reasons, normalized)

        if self.network_scope is None:
            reasons.append("no network_scope configured; scope gate skipped")

        # 2. Permission-as-code: blast radius decides the gate.
        if blast == BlastRadius.RECON:
            auth = Authorization.GRANTED
            reasons.append("read-only: granted")
        elif blast == BlastRadius.WRITE:
            auth = Authorization.GRANTED
            reasons.append("workspace-write: granted")
        else:  # DANGER
            auth = Authorization.REQUIRES_CONSENT
            reasons.append("danger-full-access: Mirror_RTC consent required")

        return PolicyDecision(tool_name, blast, auth, reasons, normalized)
