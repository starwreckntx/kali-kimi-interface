#!/usr/bin/env python3
"""verifier_core — the substrate-agnostic VERIFIER CONTRACT.

This is the candidate conjoining point (assumption A2). It contains, and only
contains, what must be shared across every substrate:

  * the verdict vocabulary        {PASS, DRIFT, GAP, ADJUDICATE}
  * the provenance hash-chain     (instruction_hash, trace_hash, predicate_id,
                                    verdict, adjudicator_id, prev_hash)
  * the three-role separation     SELECTOR != GENERATOR != VERIFIER

There are **no substrate assumptions inside this file**. It does not know what a
narrator is, what a robot is, what an instruction "means", or how a trace is
captured. Adapters (adapter_narrator.py, adapter_robotics.py) translate their
substrate into a `PredicateOutcome`; the core is the notary that mints a verdict
from that outcome and chains it. It is deliberately import-light (stdlib only) so
that "one unmodified core carries both adapters" is a checkable claim, not prose.

Design seam (invariant 1 — the verdict is authored by a deterministic predicate or
a human, never a generator):

    The *decision content* — did execution leave the licensed region (drift), was a
    requirement left unmet (gap), is the case even decidable — is authored upstream
    by the adapter's deterministic predicate or by a human adjudicator, and arrives
    as a `PredicateOutcome`. The core applies a fixed, substrate-agnostic mapping
    from that outcome to a verdict symbol and notarises it. The core is the notary;
    the judge is the predicate or the human. A generator (policy, narrator, actuation
    controller, VLM-as-judge) can NEVER occupy the `authority` field — the type
    system has no member for it, and `verify()` raises if one is smuggled in.

Usage:
    from verifier_core import (VerifierCore, Instruction, ExecutionTrace,
                               PredicateOutcome, Authority, Verdict)

    core = VerifierCore(predicate_set_version="v1")
    instr = Instruction("i1", payload="open the drawer", authored_by="calvin.dataset")
    trace = ExecutionTrace("t1", payload="{...state log...}", produced_by="policy.ckpt42")
    outcome = PredicateOutcome(                       # authored by the ADAPTER's predicate
        predicate_id="open_drawer", decidable=True, drift=False, gap=False,
        authority=Authority.DETERMINISTIC, rationale="drawer joint delta +0.11m")
    verdict, entry = core.verify(instr, trace, outcome)
    assert core.chain.validate()
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

GENESIS_HASH = "0" * 64


# --------------------------------------------------------------------------- #
# Verdict vocabulary (substrate-agnostic — shared, unforked)
# --------------------------------------------------------------------------- #
class Verdict(str, Enum):
    PASS = "PASS"            # decidable, execution stayed inside the licensed region
    DRIFT = "DRIFT"         # decidable, execution left the licensed region
    GAP = "GAP"             # decidable, an instruction requirement was left unmet
    ADJUDICATE = "ADJUDICATE"  # not deterministically decidable -> human queue


class Authority(str, Enum):
    """Who is permitted to author a verdict. There is deliberately NO generator/
    advisory member: a learned model can populate `PredicateOutcome.advisory` but
    can never sit here (invariant 2)."""
    DETERMINISTIC = "deterministic"   # a versioned acceptance predicate
    HUMAN = "human"                   # an operator adjudication


class VerdictAuthorityError(RuntimeError):
    """Raised if anything other than a deterministic predicate or a human tries to
    author a decidable verdict."""


# --------------------------------------------------------------------------- #
# Opaque envelopes — the core hashes these but never interprets their payloads.
# --------------------------------------------------------------------------- #
def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Instruction:
    """Authored by the SELECTOR (upstream authority). Payload is opaque to the core."""
    instruction_id: str
    payload: str
    authored_by: str = "selector"

    def hash(self) -> str:
        return _sha256(f"{self.instruction_id}\x1f{self.payload}\x1f{self.authored_by}")


@dataclass(frozen=True)
class ExecutionTrace:
    """Produced by the GENERATOR (policy / narrator / controller). Recorded, hashed,
    and fed to the predicate — but NEVER trusted to author the verdict."""
    trace_id: str
    payload: str
    produced_by: str = "generator"

    def hash(self) -> str:
        return _sha256(f"{self.trace_id}\x1f{self.payload}\x1f{self.produced_by}")


@dataclass
class PredicateOutcome:
    """The adapter's verdict content. DRIFT and GAP are orthogonal booleans and are
    carried separately all the way into provenance — the core never averages them
    (invariant 4).

    `decidable=False` means the acceptance predicate could not deterministically
    decide (e.g. an under-specified, set-valued instruction) -> the core returns
    ADJUDICATE. `advisory` may carry learned-model hints for the human queue; it can
    never flip `decidable` to True."""
    predicate_id: str
    decidable: bool
    drift: bool
    gap: bool
    authority: Authority
    rationale: str = ""
    adjudication_reason: Optional[str] = None
    advisory: Optional[Dict] = None


# --------------------------------------------------------------------------- #
# Provenance chain (invariant 5) — append-only, SHA-256, verifiable.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ProvenanceEntry:
    seq: int
    instruction_hash: str
    trace_hash: str
    predicate_id: str
    predicate_set_version: str
    verdict: str
    drift: bool
    gap: bool
    adjudicator_id: str
    authority: str
    substrate: str
    prev_hash: str
    entry_hash: str = ""

    def _preimage(self) -> str:
        # entry_hash is excluded from its own preimage; everything else is bound.
        return "\x1f".join([
            str(self.seq), self.instruction_hash, self.trace_hash, self.predicate_id,
            self.predicate_set_version, self.verdict, str(self.drift), str(self.gap),
            self.adjudicator_id, self.authority, self.substrate, self.prev_hash,
        ])

    def compute_hash(self) -> str:
        return _sha256(self._preimage())

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


class ProvenanceChain:
    """A single append-only hash-chained ledger. Both substrates can share one chain
    (the DONE criterion allows one chain OR two chains under one schema)."""

    def __init__(self) -> None:
        self._entries: List[ProvenanceEntry] = []

    @property
    def entries(self) -> List[ProvenanceEntry]:
        return list(self._entries)

    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def append(self, fields: Dict) -> ProvenanceEntry:
        prev = self.head_hash
        draft = ProvenanceEntry(
            seq=len(self._entries),
            prev_hash=prev,
            **fields,
        )
        entry = ProvenanceEntry(**{**draft.to_dict(), "entry_hash": draft.compute_hash()})
        self._entries.append(entry)
        return entry

    def validate(self) -> bool:
        """Re-walk the chain: every link points to the prior hash and every entry
        hash recomputes. Returns True iff the ledger is intact."""
        prev = GENESIS_HASH
        for i, e in enumerate(self._entries):
            if e.seq != i or e.prev_hash != prev:
                return False
            recomputed = ProvenanceEntry(**{**e.to_dict(), "entry_hash": ""}).compute_hash()
            if recomputed != e.entry_hash:
                return False
            prev = e.entry_hash
        return True

    def to_jsonl(self) -> str:
        return "\n".join(e.to_json() for e in self._entries)


# --------------------------------------------------------------------------- #
# The core: notary + fixed verdict mapping. This is the whole conjoining point.
# --------------------------------------------------------------------------- #
class VerifierCore:
    def __init__(self, predicate_set_version: str = "v1",
                 chain: Optional[ProvenanceChain] = None) -> None:
        self.predicate_set_version = predicate_set_version
        self.chain = chain if chain is not None else ProvenanceChain()

    @staticmethod
    def _map_verdict(outcome: PredicateOutcome) -> Verdict:
        """The fixed, substrate-agnostic (decidable, drift, gap) -> verdict mapping.
        DRIFT dominates a co-occurring GAP in the *summary symbol* (leaving the
        licensed region is a stronger integrity failure than an omission), but both
        booleans are recorded independently so downstream rates are never averaged."""
        if not outcome.decidable:
            return Verdict.ADJUDICATE
        if outcome.drift:
            return Verdict.DRIFT
        if outcome.gap:
            return Verdict.GAP
        return Verdict.PASS

    def verify(
        self,
        instruction: Instruction,
        trace: ExecutionTrace,
        outcome: PredicateOutcome,
        substrate: str = "unspecified",
        adjudicator_id: Optional[str] = None,
    ) -> Tuple[Verdict, ProvenanceEntry]:
        # ---- enforce verdict authorship (invariants 1 & 2) -------------------
        if not isinstance(outcome.authority, Authority):
            raise VerdictAuthorityError(
                f"authority must be an Authority member, got {outcome.authority!r}")
        if outcome.decidable and outcome.authority == Authority.HUMAN and not adjudicator_id:
            raise VerdictAuthorityError(
                "a decidable HUMAN verdict requires an adjudicator_id")

        verdict = self._map_verdict(outcome)

        # who is on record as the adjudicator for this entry
        if verdict is Verdict.ADJUDICATE:
            resolved_adjudicator = adjudicator_id or "queue:pending"
        elif outcome.authority == Authority.HUMAN:
            resolved_adjudicator = f"human:{adjudicator_id}"
        else:
            resolved_adjudicator = f"deterministic:{outcome.predicate_id}"

        entry = self.chain.append({
            "instruction_hash": instruction.hash(),
            "trace_hash": trace.hash(),
            "predicate_id": outcome.predicate_id,
            "predicate_set_version": self.predicate_set_version,
            "verdict": verdict.value,
            "drift": bool(outcome.drift),
            "gap": bool(outcome.gap),
            "adjudicator_id": resolved_adjudicator,
            "authority": outcome.authority.value,
            "substrate": substrate,
        })
        return verdict, entry


__all__ = [
    "Verdict", "Authority", "VerdictAuthorityError",
    "Instruction", "ExecutionTrace", "PredicateOutcome",
    "ProvenanceEntry", "ProvenanceChain", "VerifierCore", "GENESIS_HASH",
]
