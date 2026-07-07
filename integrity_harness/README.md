# Substrate-Agnostic Instruction-Execution Integrity Harness — Round 0

**State: `REAL` on the mandate's four operational DONE criteria, against Round-0
held-out load. That held-out load is *reserved synthetic fixtures*, not real rollouts —
see the honest-limitations section of `reports/A2_certification.md`. This is Phase 0:
offline, dataset-only, NO enforcement, NO online control.**

One integrity harness whose **verifier core is substrate-agnostic**. The same core
carries two adapters that break faithfulness in fundamentally different ways, and emits
the same verdict vocabulary over the same hash-chained provenance:

- **platformed / narrator** — faithfulness = *equality* against a discrete decision
  record (the crisp floor). Reuses the in-repo Boundary Integrity Evaluator (`redteam/`).
- **embodied / robotics** — faithfulness = *membership* in an under-specified acceptance
  region (the set-valued case). Targets **CALVIN** (Mees et al. 2022).

The **conjoining point** is the demonstrated intersection where both adapters plug into
**one unmodified** `verifier_core.py`. It was treated as a hypothesis (A2) and
**certified by execution**, not asserted from a diagram.

## The contract (the whole conjoining point)

```
verify(instruction, execution_trace) -> (verdict, provenance)
  verdict     ∈ { PASS, DRIFT, GAP, ADJUDICATE }
  provenance  = append-only SHA-256 hash-chain entry
```

- **DRIFT** — execution left the licensed region (did something unauthorized).
- **GAP** — an instruction requirement was left unmet (omission).
- DRIFT and GAP are **orthogonal** and reported as **separate rates, never averaged**.
- The verdict is authored by a **deterministic predicate or a human — never a
  generator**. A learned model may only *populate the adjudication queue* (advisory).

## Layout

```
integrity_harness/
├── verifier_core.py            # substrate-agnostic contract (notary, not judge)
├── certify_a1.py               # A1: deterministic-floor measurement on CALVIN
├── adapters/
│   ├── adapter_narrator.py     # platformed / equality adapter (BIE decision records)
│   └── adapter_robotics.py     # embodied / membership adapter (CALVIN state-delta)
├── probes/
│   └── probe_execution_drift.py# two-tier DRIFT/GAP probe over BOTH substrates
├── data/                       # source-of-record (pulled dataset + frozen fixtures)
│   ├── calvin_annotations.json #   389 real CALVIN instructions / 34 task classes
│   ├── calvin_predicates.json  #   34 deterministic success predicates (frozen v1)
│   ├── calvin_traces.json      #   recorded state-log fixtures (Phase-0 offline)
│   └── narrator_records.json   #   decision records + frozen narrator traces
├── reports/
│   ├── A1_certification.md      #   floor size, held-out reserved
│   ├── A2_certification.md      #   core-unchanged proof + honest limitations
│   └── a2_snapshots/            #   pre-adapter core baseline (for the A2 diff)
└── tests/test_integrity_harness.py
```

## Run it

```bash
# A1 — deterministic-floor size on CALVIN (structural 100%, held-out operational 93.3%)
python3 integrity_harness/certify_a1.py

# each adapter, self-checked against ground-truth fixtures
python3 integrity_harness/adapters/adapter_narrator.py
python3 integrity_harness/adapters/adapter_robotics.py

# both substrates -> one core -> one shared chain; prints DONE criteria + state
python3 integrity_harness/probes/probe_execution_drift.py

# A2 — prove the core did not change to carry the second adapter
diff integrity_harness/reports/a2_snapshots/verifier_core.before_narrator.py \
     integrity_harness/verifier_core.py            # -> empty

# tests (pytest-shaped; runs without pytest too)
python3 integrity_harness/tests/test_integrity_harness.py
```

## Results (Round 0)

| Assumption | Result |
|---|---|
| **A1** deterministic-floor exists | **HOLDS.** Structural ceiling 100% (389/389); conservative held-out operational floor **93.3%**, **0% misfire**. |
| **A2** conjoining point exists | **HOLDS.** `verifier_core.py` **byte-identical** after carrying both adapters (0 lines changed). Verdict vocabulary unforked; one 54-entry chain validates across both substrates; held-out catch-rate non-zero on both. |

## What is NOT yet done (carried to Round 1)

- Held-out load is **synthetic reserved fixtures**, not real CALVIN rollouts or real
  narrator outputs. 100% held-out catch-rate demonstrates predicate *correctness*, not
  *generalisation*. Round 1 swaps in real traces and re-measures; the catch-rate drop is
  the real signal.
- `adapter_robotics.completed_tasks()` mirrors CALVIN `get_task_info()` but is not yet
  cross-checked against the simulator's own labels on real episodes.
- No enforcement / veto tier. This is a **measurement floor**, deliberately built before
  any veto tier (a robot can be flawlessly safe and completely unfaithful; CBFs certify
  safety, not fidelity).

See `reports/A1_certification.md` and `reports/A2_certification.md` for the full,
un-softened accounting.
