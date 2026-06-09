#!/usr/bin/env python3
"""
Mirror_RTC — human consent gate for the KKI governance layer (IRP Task 3.11 / 3.3).

For any `danger-full-access` action the operator is the non-negotiable apex: the action
cannot proceed without an explicit, per-action `APPROVE <nonce>` response. The gate is
*default-deny* — denial, timeout, a wrong nonce, or no available operator all resolve to
DENIED, and the action is recorded as a boundary-consent pending item.

The prompt mechanism is pluggable via a callback so it can be a CLI, a WebSocket, or a
test stub. The default is an interactive stdin prompt with a timeout (POSIX `select`).

Usage:
    from governance.consent import ConsentGate
    gate = ConsentGate(prompt_fn=my_prompt, timeout=30)
    decision = gate.request(tool="nmap", target="10.0.0.5",
                            blast_radius="DANGER", est_impact="SYN scan, 1 host")
    if decision.approved:
        ...   # only now may the action run
"""

from __future__ import annotations

import secrets
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class ConsentResult(Enum):
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    NO_OPERATOR = "no_operator"


@dataclass
class ConsentRequest:
    action_id: str
    tool: str
    target: str
    blast_radius: str
    nonce: str
    est_impact: str
    created_at: str
    operator: Optional[str] = None


@dataclass
class ConsentDecision:
    request: ConsentRequest
    result: ConsentResult
    responded_at: str
    raw_response: Optional[str] = None

    @property
    def approved(self) -> bool:
        return self.result == ConsentResult.APPROVED

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["result"] = self.result.value
        return d


# A prompt function receives the request and must return the operator's raw response
# string (e.g. "APPROVE <nonce>") or None to signal no response / timeout.
PromptFn = Callable[[ConsentRequest], Optional[str]]


def _default_cli_prompt(req: ConsentRequest, timeout: float) -> Optional[str]:
    """Interactive stdin prompt with a timeout. Returns the typed line, or None."""
    banner = (
        f"\n{'!'*60}\n"
        f"[Mirror_RTC] OPERATOR AUTHORIZATION REQUIRED\n"
        f"  Tool        : {req.tool}\n"
        f"  Target      : {req.target}\n"
        f"  Blast radius: {req.blast_radius}\n"
        f"  Est. impact : {req.est_impact}\n"
        f"  Reply 'APPROVE {req.nonce}' to authorize, or 'DENY'.\n"
        f"  Default on {int(timeout)}s timeout: DENY\n"
        f"{'!'*60}\n> "
    )
    sys.stdout.write(banner)
    sys.stdout.flush()
    if not sys.stdin or not sys.stdin.isatty():
        return None
    try:
        import select
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if ready:
            return sys.stdin.readline().strip()
        return None
    except Exception:
        return None


class ConsentGate:
    """Per-action human authorization gate (default-deny)."""

    def __init__(
        self,
        prompt_fn: Optional[PromptFn] = None,
        timeout: float = 30.0,
        operator: Optional[str] = None,
    ):
        self.prompt_fn = prompt_fn
        self.timeout = timeout
        self.operator = operator
        # boundary-consent registry for session-close logging (IRP 4.3)
        self.pending: List[ConsentRequest] = []
        self.unauthorized: List[ConsentDecision] = []
        self.decisions: List[ConsentDecision] = []

    def request(self, tool: str, target: str, blast_radius: str, est_impact: str = "") -> ConsentDecision:
        nonce = secrets.token_hex(16)
        req = ConsentRequest(
            action_id=secrets.token_hex(8),
            tool=tool, target=target, blast_radius=blast_radius, nonce=nonce,
            est_impact=est_impact, created_at=datetime.now().isoformat(),
            operator=self.operator,
        )
        self.pending.append(req)

        raw: Optional[str]
        if self.prompt_fn is not None:
            try:
                raw = self.prompt_fn(req)
            except Exception:
                raw = None
        else:
            raw = _default_cli_prompt(req, self.timeout)

        decision = self._evaluate(req, raw)
        self.pending.remove(req)
        self.decisions.append(decision)
        if not decision.approved:
            self.unauthorized.append(decision)
        return decision

    def _evaluate(self, req: ConsentRequest, raw: Optional[str]) -> ConsentDecision:
        now = datetime.now().isoformat()
        if raw is None:
            # No operator available, or the wait elapsed: treat as timeout/no-operator.
            result = ConsentResult.NO_OPERATOR if self.prompt_fn is None and not (sys.stdin and sys.stdin.isatty()) else ConsentResult.TIMEOUT
            return ConsentDecision(req, result, now, raw_response=None)
        text = raw.strip()
        parts = text.split()
        # Exact protocol: APPROVE <nonce>. Constant-time nonce compare.
        if len(parts) == 2 and parts[0].upper() == "APPROVE" and secrets.compare_digest(parts[1], req.nonce):
            return ConsentDecision(req, ConsentResult.APPROVED, now, raw_response=text)
        return ConsentDecision(req, ConsentResult.DENIED, now, raw_response=text)

    def boundary_report(self) -> Dict[str, Any]:
        """Unresolved + denied actions, for the Mnemosyne boundary log at session close."""
        return {
            "still_pending": [asdict(r) for r in self.pending],
            "unauthorized": [d.to_dict() for d in self.unauthorized],
            "total_requests": len(self.decisions),
            "approved": sum(1 for d in self.decisions if d.approved),
        }
