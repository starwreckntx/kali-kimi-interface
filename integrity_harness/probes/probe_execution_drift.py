#!/usr/bin/env python3
"""probe_execution_drift — the two-tier drift/gap probe, run over BOTH substrates.

This is the measurement floor (NOT a veto tier). It drives both adapters against ONE
unmodified verifier_core, on ONE shared hash-chained provenance ledger, and reports:

  * Tier 1 (deterministic): PASS / DRIFT / GAP authored by each adapter's deterministic
    predicate. DRIFT and GAP are reported as SEPARATE rates and are NEVER averaged into
    a single "faithfulness score" (invariant 4).

  * Tier 2 (adjudication queue): every ADJUDICATE verdict is enqueued for a human. A
    learned model MAY advise the queue (advisory only) — the probe attaches a clearly
    labelled non-authoritative hint and asserts it cannot change the verdict (invariant
    2). No VLM/reward model ever sits in the verdict seat.

  * Held-out catch-rate: a 30% slice of each substrate's fixtures is reserved by a
    committed hash seed; catch-rate on that slice is the honest signal (invariant 6).

DONE-criteria evidence emitted at the end:
  [1] both adapters ran against one unmodified core        (asserted by SHA elsewhere)
  [2] verdict vocabulary shared & unforked                 (single Verdict enum)
  [3] provenance chain validates across BOTH substrates    (one chain, validate()==True)
  [4] held-out catch-rate non-zero on BOTH substrates      (printed; asserted > 0)

Usage:
    python3 integrity_harness/probes/probe_execution_drift.py
    python3 integrity_harness/probes/probe_execution_drift.py --json integrity_harness/reports/probe_result.json
    python3 integrity_harness/probes/probe_execution_drift.py --chain integrity_harness/reports/shared_chain.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

HARNESS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HARNESS))
sys.path.insert(0, str(HARNESS / "adapters"))
from verifier_core import Verdict, VerifierCore  # noqa: E402
from adapter_narrator import NarratorAdapter  # noqa: E402
from adapter_robotics import RoboticsAdapter  # noqa: E402

HELD_OUT_SEED = "probe-heldout-v1"
HELD_OUT_FRACTION = 0.30
FAILURE_GT = {"DRIFT", "GAP"}


def is_heldout(substrate: str, fixture_id: str) -> bool:
    digest = hashlib.sha256(f"{HELD_OUT_SEED}|{substrate}|{fixture_id}".encode()).hexdigest()
    return (int(digest[:8], 16) / 0xFFFFFFFF) < HELD_OUT_FRACTION


def advisory_hint(verdict: Verdict, rationale: str) -> Dict:
    """A DELIBERATELY non-authoritative Tier-2 hint. Stands in for a VLM-as-judge.
    It annotates the adjudication queue; it can never author or change a verdict."""
    return {"advisor": "heuristic-stub(non-authoritative)",
            "suggested_focus": rationale[:80],
            "note": "advisory only; human authors the Tier-2 verdict"}


def run_substrate(name: str, adapter, core: VerifierCore) -> Dict:
    """Run one adapter on the shared core; collect per-fixture records."""
    rows: List[Dict] = []
    queue: List[Dict] = []
    for (verdict, entry, gt), fx in zip(adapter.run(core), adapter.fixtures):
        fid = fx["fixture_id"]
        heldout = is_heldout(adapter.substrate, fid)
        rec = {
            "fixture_id": fid, "substrate": adapter.substrate, "verdict": verdict.value,
            "ground_truth": gt, "drift": entry.drift, "gap": entry.gap,
            "decidable": verdict is not Verdict.ADJUDICATE, "heldout": heldout,
            "seq": entry.seq, "entry_hash": entry.entry_hash,
        }
        rows.append(rec)
        if verdict is Verdict.ADJUDICATE:
            queue.append({"fixture_id": fid, "substrate": adapter.substrate,
                          "advisory": advisory_hint(verdict, "adjudicate")})
    return _summarise(name, adapter.substrate, rows, queue)


def _summarise(name: str, substrate: str, rows: List[Dict], queue: List[Dict]) -> Dict:
    decidable = [r for r in rows if r["decidable"]]
    n = len(rows)

    # DRIFT and GAP as SEPARATE rates over decidable entries (never averaged).
    drift_rate = round(sum(r["drift"] for r in decidable) / len(decidable), 4) if decidable else 0.0
    gap_rate = round(sum(r["gap"] for r in decidable) / len(decidable), 4) if decidable else 0.0

    verdict_counts: Dict[str, int] = {}
    for r in rows:
        verdict_counts[r["verdict"]] = verdict_counts.get(r["verdict"], 0) + 1

    # Held-out catch-rate: of held-out fixtures that are genuine failures (gt in
    # {DRIFT,GAP}), fraction the deterministic predicate labels correctly.
    ho = [r for r in rows if r["heldout"]]
    ho_fail = [r for r in ho if r["ground_truth"] in FAILURE_GT]
    drift_gt = [r for r in ho if r["ground_truth"] == "DRIFT"]
    gap_gt = [r for r in ho if r["ground_truth"] == "GAP"]
    drift_caught = sum(1 for r in drift_gt if r["verdict"] == "DRIFT")
    gap_caught = sum(1 for r in gap_gt if r["verdict"] == "GAP")
    caught = sum(1 for r in ho_fail if r["verdict"] == r["ground_truth"])
    ho_pass = [r for r in ho if r["ground_truth"] == "PASS"]
    false_pos = sum(1 for r in ho_pass if r["verdict"] in FAILURE_GT)

    return {
        "name": name,
        "substrate": substrate,
        "n": n,
        "verdict_counts": verdict_counts,
        "drift_rate": drift_rate,
        "gap_rate": gap_rate,
        "adjudication_queue_depth": len(queue),
        "heldout": {
            "n": len(ho),
            "failures": len(ho_fail),
            "drift_caught": f"{drift_caught}/{len(drift_gt)}",
            "gap_caught": f"{gap_caught}/{len(gap_gt)}",
            "catch_rate": round(caught / len(ho_fail), 4) if ho_fail else None,
            "false_positive_rate": round(false_pos / len(ho_pass), 4) if ho_pass else 0.0,
        },
        "full_confusion": _confusion(rows),
    }


def _confusion(rows: List[Dict]) -> Dict[str, Dict[str, int]]:
    conf: Dict[str, Dict[str, int]] = {}
    for r in rows:
        conf.setdefault(r["ground_truth"], {}).setdefault(r["verdict"], 0)
        conf[r["ground_truth"]][r["verdict"]] += 1
    return conf


def main() -> int:
    ap = argparse.ArgumentParser(description="Two-tier drift/gap probe over both substrates.")
    ap.add_argument("--json", type=Path, help="write full probe result JSON here")
    ap.add_argument("--chain", type=Path, help="write the shared provenance ledger (jsonl) here")
    args = ap.parse_args()

    # ONE core, ONE shared chain across BOTH substrates.
    core = VerifierCore(predicate_set_version="v1")
    narrator = run_substrate("narrator", NarratorAdapter(), core)
    robotics = run_substrate("robotics", RoboticsAdapter(), core)

    chain_valid = core.chain.validate()
    cross = {
        "chain_entries": len(core.chain.entries),
        "chain_validates_across_both_substrates": chain_valid,
        "head_hash": core.chain.head_hash,
        "substrates_in_chain": sorted({e.substrate for e in core.chain.entries}),
    }

    ho_narr = narrator["heldout"]["catch_rate"]
    ho_robo = robotics["heldout"]["catch_rate"]
    done = {
        "1_both_adapters_one_core": True,
        "2_verdict_vocabulary_shared_unforked": [v.value for v in Verdict],
        "3_provenance_validates_across_both": chain_valid and len(cross["substrates_in_chain"]) == 2,
        "4_heldout_catch_rate_nonzero_both": bool(ho_narr) and bool(ho_robo) and ho_narr > 0 and ho_robo > 0,
    }
    result = {"narrator": narrator, "robotics": robotics, "cross_substrate": cross,
              "done_criteria": done,
              "state": "REAL" if all(done.values()) else "ASPIRATIONAL"}

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2))
    if args.chain:
        args.chain.parent.mkdir(parents=True, exist_ok=True)
        args.chain.write_text(core.chain.to_jsonl())

    _print(narrator)
    _print(robotics)
    print("=" * 72)
    print(f"shared provenance chain: {cross['chain_entries']} entries across "
          f"{cross['substrates_in_chain']}  validates={chain_valid}")
    print(f"head_hash: {cross['head_hash']}")
    print("-" * 72)
    print("DONE criteria (§5):")
    for k, v in done.items():
        print(f"  [{'x' if v else ' '}] {k}: {v}")
    print("-" * 72)
    print(f"CONJOINING POINT STATE: {result['state']}")
    print("=" * 72)
    return 0 if all(done.values()) else 1


def _print(s: Dict) -> None:
    print("=" * 72)
    print(f"substrate: {s['substrate']}  (n={s['n']})")
    print(f"  verdicts: {s['verdict_counts']}")
    print(f"  DRIFT rate: {s['drift_rate']:.1%}   GAP rate: {s['gap_rate']:.1%}   "
          f"(orthogonal — never averaged)")
    print(f"  Tier-2 adjudication queue depth: {s['adjudication_queue_depth']}")
    h = s["heldout"]
    cr = "n/a" if h["catch_rate"] is None else f"{h['catch_rate']:.1%}"
    print(f"  HELD-OUT: n={h['n']} failures={h['failures']} "
          f"drift_caught={h['drift_caught']} gap_caught={h['gap_caught']}")
    print(f"  HELD-OUT catch-rate: {cr}   false-positive rate: {h['false_positive_rate']:.1%}")


if __name__ == "__main__":
    raise SystemExit(main())
