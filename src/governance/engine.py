#!/usr/bin/env python3
"""
GovernedExecutor — the governance seam that wraps KKI's SecurityToolExecutor (Weave / IRP
L3-L4). It enforces the full IRP pipeline on every proposed tool call:

    decision-log -> policy.evaluate -> binary attestation -> Mirror_RTC consent
                 -> execute (only if cleared) -> execution-log

Core invariant: a `danger-full-access` tool can NEVER reach the underlying executor without
an approving Mirror_RTC consent decision. Policy alone cannot grant DANGER — it returns
REQUIRES_CONSENT, and only an operator `APPROVE <nonce>` clears the gate. On any denial the
underlying executor is never called.

Usage (library):
    from governance.engine import GovernedExecutor
    gov = GovernedExecutor(network_scope=["10.0.0.0/8"], consent_prompt=my_prompt)
    out = gov.execute("nmap_scan", {"target": "10.0.0.5", "scan_type": "syn"})
    if out.allowed: ...

Usage (CLI — safe governance preview, executes nothing):
    python3 -m src.governance.engine --tool nmap_scan --target 10.0.0.5 \
        --permission danger-full-access --scope 10.0.0.0/8
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from .policy import PolicyEngine, Authorization, BlastRadius, PolicyDecision
    from .attestation import attest_binary, Attestation
    from .consent import ConsentGate, ConsentDecision, PromptFn
    from .audit import AuditLog
except ImportError:  # direct execution
    from policy import PolicyEngine, Authorization, BlastRadius, PolicyDecision
    from attestation import attest_binary, Attestation
    from consent import ConsentGate, ConsentDecision, PromptFn
    from audit import AuditLog


def _load_harness():
    """Import the sibling harness + registry, tolerating both package and flat layouts."""
    try:
        from ..harness_integration import SecurityToolExecutor
        from ..tool_registry import VerifiableToolRegistry
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from harness_integration import SecurityToolExecutor  # type: ignore
        from tool_registry import VerifiableToolRegistry       # type: ignore
    return SecurityToolExecutor, VerifiableToolRegistry


@dataclass
class ExecutionPreCheck:
    """Read-only pre-flight summary of a proposed call (no consent, no execution).

    Used to enrich a Mirror_RTC challenge with estimated blast radius before the operator
    is prompted, and as a safe inspection surface for callers.
    """
    tool_name: str
    permission_level: str
    requires_consent: bool
    network_scope_ok: bool
    target_normalized: str
    safe_flags: List[str]
    rejected_flags: List[str]
    estimated_blast_radius: str   # "low" | "medium" | "high"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GovernedResult:
    tool: str
    allowed: bool
    authorization: str
    blast_radius: str
    denial_reason: Optional[str]
    policy: Dict[str, Any]
    attestation: Optional[Dict[str, Any]]
    consent: Optional[Dict[str, Any]]
    result: Optional[Dict[str, Any]]      # underlying executor result, or None if blocked
    audit_seq: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class GovernedExecutor:
    def __init__(
        self,
        executor: Any = None,
        registry: Any = None,
        policy: Optional[PolicyEngine] = None,
        consent: Optional[ConsentGate] = None,
        audit: Optional[AuditLog] = None,
        network_scope: Optional[List[str]] = None,
        consent_prompt: Optional[PromptFn] = None,
        consent_timeout: float = 30.0,
    ):
        if executor is None or registry is None:
            SecurityToolExecutor, VerifiableToolRegistry = _load_harness()
            executor = executor or SecurityToolExecutor()
            registry = registry or VerifiableToolRegistry()
        self.executor = executor
        self.registry = registry
        self.policy = policy or PolicyEngine(network_scope=network_scope)
        self.consent = consent or ConsentGate(prompt_fn=consent_prompt, timeout=consent_timeout)
        self.audit = audit or AuditLog()

    # --- permission/identity resolution ---------------------------------------------

    def _binary_name(self, tool_name: str) -> str:
        return self.policy.tool_to_binary.get(tool_name, tool_name)

    def _permission_for(self, tool_name: str) -> str:
        # Prefer the harness-declared permission; fall back to the registry; fail closed.
        getter = getattr(self.executor, "get_tool_spec", None)
        if callable(getter):
            spec = getter(tool_name)
            if spec is not None and getattr(spec, "required_permission", None):
                return spec.required_permission
        tv = self.registry.get(self._binary_name(tool_name)) if self.registry else None
        if tv is not None and getattr(tv, "permission", None):
            return tv.permission
        return "danger-full-access"  # unknown => most restrictive gate

    def _attest(self, tool_name: str) -> Optional[Attestation]:
        tv = self.registry.get(self._binary_name(tool_name)) if self.registry else None
        if tv is None:
            return attest_binary(self._binary_name(tool_name))
        return attest_binary(tv.binary_path or self._binary_name(tool_name), expected_sha256=tv.sha256)

    # --- the governed execution pipeline --------------------------------------------

    def _gate(
        self, tool_name: str, params: Dict[str, Any], permission: Optional[str] = None,
    ) -> Tuple[Optional[GovernedResult], PolicyDecision, Optional[Dict[str, Any]], Optional[Dict[str, Any]], List[int]]:
        """Run the full governance gate (policy -> attestation -> consent) but do NOT
        execute. Returns (blocked_result, decision, attestation, consent, audit_seqs).
        ``blocked_result`` is None when the action is cleared to run.
        """
        seqs: List[int] = []
        if permission is None:
            permission = self._permission_for(tool_name)

        seqs.append(self.audit.log_decision({
            "event": "proposal", "tool": tool_name, "params": params, "permission": permission,
            "operator": os.environ.get("KKI_OPERATOR_ID", "unknown"),
        }).seq)

        # 1. Policy evaluation (positive validation + permission-as-code).
        decision: PolicyDecision = self.policy.evaluate(tool_name, permission, params)
        seqs.append(self.audit.log_decision({"event": "policy", **decision.to_dict()}).seq)
        if decision.authorization == Authorization.DENIED:
            return (self._blocked(tool_name, decision, None, None,
                                  "; ".join(decision.reasons) or "policy denied", seqs),
                    decision, None, None, seqs)

        # 2. Per-invocation binary attestation.
        att = self._attest(tool_name)
        att_dict = att.to_dict() if att else None
        seqs.append(self.audit.log_integrity({"event": "attestation", **(att_dict or {})}).seq)
        if decision.blast_radius == BlastRadius.DANGER and (att is None or not att.verified):
            return (self._blocked(tool_name, decision, att_dict, None,
                                  f"attestation failed: {att.reason if att else 'no attestation'}", seqs),
                    decision, att_dict, None, seqs)

        # 3. Mirror_RTC consent for DANGER actions.
        consent_dict: Optional[Dict[str, Any]] = None
        if decision.authorization == Authorization.REQUIRES_CONSENT:
            target = str(params.get("target") or params.get("url") or params.get("host") or "?")
            # Bind the attested binary hash into the operator prompt. The SAME attestation
            # object is used for execution (execute() does not re-attest), so the operator
            # approves the exact hash that runs — closing the consent->exec TOCTOU window.
            attested = (att.sha256 if att and att.sha256 else "unattested")
            cd: ConsentDecision = self.consent.request(
                tool=self._binary_name(tool_name), target=target,
                blast_radius=decision.blast_radius.value,
                est_impact=f"{tool_name} against {target} [sha256:{attested[:16]}]",
            )
            consent_dict = cd.to_dict()
            seqs.append(self.audit.log_decision({"event": "consent", **consent_dict}).seq)
            if not cd.approved:
                return (self._blocked(tool_name, decision, att_dict, consent_dict,
                                      f"consent {cd.result.value}: operator did not authorize", seqs),
                        decision, att_dict, consent_dict, seqs)

        return None, decision, att_dict, consent_dict, seqs

    def execute(self, tool_name: str, params: Dict[str, Any]) -> GovernedResult:
        """Gate the proposal and, only if cleared, run the underlying executor."""
        blocked, decision, att_dict, consent_dict, seqs = self._gate(tool_name, params)
        if blocked is not None:
            return blocked

        # Cleared — run the underlying executor.
        try:
            result = self.executor.execute(tool_name, params)
        except Exception as e:  # executor is expected to return error dicts, but be safe
            result = {"error": f"executor raised: {e}", "tool": tool_name, "success": False}
        seqs.append(self.audit.log_execution({
            "event": "execution", "tool": tool_name,
            "returncode": result.get("returncode") if isinstance(result, dict) else None,
            "success": result.get("success", result.get("returncode", -1) == 0) if isinstance(result, dict) else None,
        }).seq)

        return GovernedResult(
            tool=tool_name, allowed=True, authorization=decision.authorization.value,
            blast_radius=decision.blast_radius.value, denial_reason=None,
            policy=decision.to_dict(), attestation=att_dict, consent=consent_dict,
            result=result if isinstance(result, dict) else {"result": str(result)},
            audit_seq=seqs,
        )

    def authorize(self, tool_name: str, params: Dict[str, Any], permission: Optional[str] = None) -> GovernedResult:
        """Run the full gate WITHOUT executing. ``allowed=True`` means the caller is
        cleared to run the action itself.

        Used for tools that are not registered in the base SecurityToolExecutor (e.g. the
        orchestrator's masscan/tshark wrappers) so they cannot bypass the governance gate.
        Pass ``permission`` explicitly to fail closed when the tool is unknown to both the
        executor and the registry.
        """
        blocked, decision, att_dict, consent_dict, seqs = self._gate(tool_name, params, permission)
        if blocked is not None:
            return blocked
        self.audit.log_decision({"event": "authorized", "tool": tool_name})
        return GovernedResult(
            tool=tool_name, allowed=True, authorization=decision.authorization.value,
            blast_radius=decision.blast_radius.value, denial_reason=None,
            policy=decision.to_dict(), attestation=att_dict, consent=consent_dict,
            result=None, audit_seq=seqs,
        )

    def preview(self, tool_name: str, params: Dict[str, Any], permission: Optional[str] = None) -> ExecutionPreCheck:
        """Side-effect-free pre-flight: evaluate policy and summarize, with no consent,
        no execution, and no audit entries."""
        if permission is None:
            permission = self._permission_for(tool_name)
        decision = self.policy.evaluate(tool_name, permission, params)
        blast_map = {BlastRadius.RECON: "low", BlastRadius.WRITE: "medium", BlastRadius.DANGER: "high"}
        flags = decision.normalized_params.get("flags")
        target = (decision.normalized_params.get("target")
                  or decision.normalized_params.get("url")
                  or decision.normalized_params.get("host") or "")
        rejected = [r for r in decision.reasons if r.startswith("policy_violation")]
        scope_ok = not any(("outside the network scope" in r) for r in decision.reasons)
        return ExecutionPreCheck(
            tool_name=tool_name, permission_level=permission,
            requires_consent=(decision.authorization == Authorization.REQUIRES_CONSENT),
            network_scope_ok=scope_ok, target_normalized=target,
            safe_flags=flags if isinstance(flags, list) else [],
            rejected_flags=rejected,
            estimated_blast_radius=blast_map.get(decision.blast_radius, "high"),
        )

    def _blocked(self, tool, decision, att_dict, consent_dict, reason, seqs) -> GovernedResult:
        self.audit.log_decision({"event": "blocked", "tool": tool, "reason": reason})
        return GovernedResult(
            tool=tool, allowed=False, authorization=decision.authorization.value,
            blast_radius=decision.blast_radius.value, denial_reason=reason,
            policy=decision.to_dict(), attestation=att_dict, consent=consent_dict,
            result=None, audit_seq=seqs,
        )

    # --- session lifecycle -----------------------------------------------------------

    def session_report(self) -> Dict[str, Any]:
        """Boundary-consent + audit summary for session close (IRP 4.3)."""
        return {
            "auditor_state": self.audit.auditor_state(),
            "boundary_consent": self.consent.boundary_report(),
        }

    def save_audit(self, path: str) -> str:
        return self.audit.save(path)


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="KKI governance preview — evaluate a proposed tool call WITHOUT executing it."
    )
    parser.add_argument("--tool", required=True, help="Harness tool name, e.g. nmap_scan")
    parser.add_argument("--target", help="target value")
    parser.add_argument("--url", help="url value")
    parser.add_argument("--flags", help="free-text flags to validate")
    parser.add_argument("--permission", help="override required_permission for the preview")
    parser.add_argument("--scope", action="append", help="network scope CIDR (repeatable)")
    args = parser.parse_args()

    params: Dict[str, Any] = {}
    if args.target:
        params["target"] = args.target
    if args.url:
        params["url"] = args.url
    if args.flags:
        params["flags"] = args.flags

    engine = PolicyEngine(network_scope=args.scope)
    permission = args.permission or "danger-full-access"
    decision = engine.evaluate(args.tool, permission, params)
    att = attest_binary(engine.tool_to_binary.get(args.tool, args.tool))

    print(json.dumps({
        "tool": args.tool,
        "permission": permission,
        "policy_decision": decision.to_dict(),
        "attestation": att.to_dict(),
        "note": "preview only — no tool was executed",
    }, indent=2))


if __name__ == "__main__":
    main()
