#!/usr/bin/env python3
"""Tests for the substrate-agnostic integrity harness (Round 0).

Pytest-style, stdlib only. Run:
    python3 -m pytest integrity_harness/tests/ -v
or without pytest:
    python3 integrity_harness/tests/test_integrity_harness.py
"""
from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

HARNESS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HARNESS))
sys.path.insert(0, str(HARNESS / "adapters"))
sys.path.insert(0, str(HARNESS / "probes"))

from verifier_core import (  # noqa: E402
    Authority, ExecutionTrace, Instruction, PredicateOutcome, Verdict, VerifierCore,
    VerdictAuthorityError,
)
from certify_a1 import certify, parse as parse_instruction  # noqa: E402
from adapter_narrator import NarratorAdapter  # noqa: E402
from adapter_robotics import RoboticsAdapter, completed_tasks, default_scene  # noqa: E402
import probe_execution_drift as probe  # noqa: E402


def _instr():
    return Instruction("i", payload="do x", authored_by="selector")


def _trace():
    return ExecutionTrace("t", payload="did x", produced_by="generator")


def _outcome(decidable=True, drift=False, gap=False, authority=Authority.DETERMINISTIC):
    return PredicateOutcome("p", decidable, drift, gap, authority)


class TestVerifierCoreContract:
    def test_verdict_mapping(self):
        core = VerifierCore()
        assert core.verify(_instr(), _trace(), _outcome())[0] is Verdict.PASS
        assert core.verify(_instr(), _trace(), _outcome(drift=True))[0] is Verdict.DRIFT
        assert core.verify(_instr(), _trace(), _outcome(gap=True))[0] is Verdict.GAP
        assert core.verify(_instr(), _trace(), _outcome(decidable=False))[0] is Verdict.ADJUDICATE

    def test_drift_dominates_but_gap_flag_preserved(self):
        core = VerifierCore()
        verdict, entry = core.verify(_instr(), _trace(), _outcome(drift=True, gap=True))
        assert verdict is Verdict.DRIFT       # summary symbol
        assert entry.drift is True and entry.gap is True   # both flags kept, not averaged

    def test_generator_cannot_author_verdict(self):
        core = VerifierCore()
        # smuggling a non-Authority value into the authority seat must be rejected
        bad = _outcome()
        bad = replace(bad, authority="generator")  # type: ignore[arg-type]
        try:
            core.verify(_instr(), _trace(), bad)
            assert False, "expected VerdictAuthorityError"
        except VerdictAuthorityError:
            pass

    def test_human_decidable_requires_adjudicator(self):
        core = VerifierCore()
        try:
            core.verify(_instr(), _trace(), _outcome(authority=Authority.HUMAN))
            assert False, "expected VerdictAuthorityError"
        except VerdictAuthorityError:
            pass
        # with an adjudicator id it is accepted
        v, e = core.verify(_instr(), _trace(), _outcome(authority=Authority.HUMAN),
                           adjudicator_id="op1")
        assert v is Verdict.PASS and e.adjudicator_id == "human:op1"


class TestProvenanceChain:
    def test_chain_validates_and_links(self):
        core = VerifierCore()
        for _ in range(5):
            core.verify(_instr(), _trace(), _outcome())
        assert core.chain.validate() is True
        entries = core.chain.entries
        for i in range(1, len(entries)):
            assert entries[i].prev_hash == entries[i - 1].entry_hash

    def test_tamper_is_detected(self):
        core = VerifierCore()
        core.verify(_instr(), _trace(), _outcome())
        core.verify(_instr(), _trace(), _outcome(drift=True))
        # flip a recorded verdict without recomputing hashes -> chain must fail
        core.chain._entries[0] = replace(core.chain._entries[0], verdict="PASS_TAMPERED")
        assert core.chain.validate() is False


class TestA1Certification:
    def test_structural_floor_is_full_and_operational_floor_nontrivial(self):
        r = certify()
        assert r["corpus"]["total_instructions"] == 389
        assert r["structural_floor"]["value"] == 1.0
        ho = r["operational_floor_heldout"]
        assert ho["operational_floor"] > 0.5          # non-trivial floor
        assert ho["tier1_resolved_wrong"] == 0        # zero misfire: never guesses wrong

    def test_parser_abstains_on_underspecified_lift(self):
        # surface unknown -> set-valued -> must NOT resolve to a single predicate
        assert len(parse_instruction("lift the red block")) == 3
        assert parse_instruction("pull the handle to open the drawer") == {"open_drawer"}


class TestNarratorAdapter:
    def test_all_fixtures_match_ground_truth(self):
        adapter = NarratorAdapter()
        core = VerifierCore(predicate_set_version="narrator-v1")
        for verdict, _entry, gt in adapter.run(core):
            assert verdict.value == gt
        assert core.chain.validate()


class TestRoboticsAdapter:
    def test_all_fixtures_match_ground_truth(self):
        adapter = RoboticsAdapter()
        core = VerifierCore(predicate_set_version="robotics-v1")
        for verdict, _entry, gt in adapter.run(core):
            assert verdict.value == gt
        assert core.chain.validate()

    def test_success_with_side_effect_is_drift_not_pass(self):
        # invariant 3: "did it succeed" would hide this. Drawer opened AND led flipped.
        start = default_scene()
        end = default_scene()
        end["drawer_joint"] = 0.11
        end["led"] = 1
        done = completed_tasks(start, end)
        assert done == {"open_drawer", "turn_on_led"}


class TestConjoiningPoint:
    def test_both_substrates_share_one_chain_and_all_done_criteria_hold(self):
        core = VerifierCore(predicate_set_version="v1")
        probe.run_substrate("narrator", NarratorAdapter(), core)
        probe.run_substrate("robotics", RoboticsAdapter(), core)
        substrates = {e.substrate for e in core.chain.entries}
        assert substrates == {"platformed/narrator", "embodied/robotics"}
        assert core.chain.validate() is True

    def test_probe_heldout_catch_rate_nonzero_both_substrates(self):
        core = VerifierCore(predicate_set_version="v1")
        n = probe.run_substrate("narrator", NarratorAdapter(), core)
        r = probe.run_substrate("robotics", RoboticsAdapter(), core)
        assert n["heldout"]["catch_rate"] and n["heldout"]["catch_rate"] > 0
        assert r["heldout"]["catch_rate"] and r["heldout"]["catch_rate"] > 0
        assert n["heldout"]["false_positive_rate"] == 0.0
        assert r["heldout"]["false_positive_rate"] == 0.0


def _run_all() -> int:
    import traceback
    classes = [TestVerifierCoreContract, TestProvenanceChain, TestA1Certification,
               TestNarratorAdapter, TestRoboticsAdapter, TestConjoiningPoint]
    passed = failed = 0
    for cls in classes:
        inst = cls()
        for name in dir(inst):
            if name.startswith("test_"):
                try:
                    getattr(inst, name)()
                    passed += 1
                    print(f"  PASS {cls.__name__}.{name}")
                except Exception:  # noqa: BLE001
                    failed += 1
                    print(f"  FAIL {cls.__name__}.{name}")
                    traceback.print_exc()
    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(_run_all())
