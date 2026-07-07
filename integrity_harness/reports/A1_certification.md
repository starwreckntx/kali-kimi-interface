# A1 Certification — Deterministic-Floor Existence

**State: CERTIFIED — A1 HOLDS.**
**Assumption:** *A non-trivial fraction of the target dataset's instructions reduce to a deterministically checkable state predicate.*
**Target dataset:** CALVIN (Mees et al. 2022, RA-L, arXiv:2112.03227).
**Predicate-set version (frozen variable):** `v1`.
**Held-out seed:** `A1-calvin-v1`, held-out fraction `0.30` — reserved **before** any parser rule was written.

Reproduce: `python3 integrity_harness/certify_a1.py --json integrity_harness/reports/a1_result.json`

---

## The number

| Floor | Definition | Value |
|---|---|---|
| **Structural (ceiling)** | fraction of instructions whose dataset-assigned task class carries a deterministic predicate | **100.0%** (389/389) |
| **Operational — train** | raw string → unique correct predicate, no ML, no scene access | 95.9% |
| **Operational — HELD-OUT** | same, on the reserved slice | **93.3%** (112/120) |
| Misfire (held-out) | raw string → *wrong* predicate (Tier-1 fires on the wrong check) | **0.0%** |
| Routed to Tier-2 (held-out) | ambiguous or unrecognised → human adjudication | 6.7% (8/120) |

**The deterministic floor is large and real.** The rest of the mandate stands.

---

## Why two numbers, and why the gap is the honest part

The **structural floor is 100% by construction**: CALVIN is a closed-vocabulary,
curated benchmark in which every language annotation is labelled with exactly one of
34 task classes, and every one of those 34 classes ships a deterministic success
predicate (a `start_info → end_info` state-delta check; see
`data/calvin_predicates.json`). So *if you trust the dataset's own task label*, every
instruction is Tier-1-checkable. That is the ceiling, and it is not self-congratulation
to state it — it is the reason CALVIN was chosen over an open-vocabulary set: **a
deterministic floor can only exist where instructions carry recoverable state.**

But the ceiling over-counts, because at verification time the harness is handed a raw
instruction string, not the dataset's label. The **operational floor** measures what a
conservative, no-ML parser can actually reduce to a *unique* predicate from text alone.
That number is **93.3% on held-out** — non-trivial, and materially below the ceiling.
The gap between 100% and 93.3% is not parser weakness; it is **genuine dataset
under-specification**, and the parser surfaces it honestly instead of hiding it.

### The 6.7% that route to Tier-2 (held-out)

Every held-out Tier-2 routing is a surface-under-specified lift:

```
"lift the red block up"                 label=lift_red_block_table
"lift the blue block"                   label=lift_blue_block_table
"grasp the blue block and lift it up"   label=lift_blue_block_table
"grasp the blue block, then lift it up" label=lift_blue_block_table
"pick up the pink block"                label=lift_pink_block_table
"lift the pink block up"                label=lift_pink_block_table
"grasp the pink block and lift it up"   label=lift_pink_block_table
```

The instruction names a colour but not a surface, yet the deterministic predicate
differs by surface (table lift ≥5 cm, slider lift ≥3 cm, drawer lift ≥5 cm from
different reference planes). From text alone the predicate is not uniquely determined,
so the parser returns the candidate **set** `{table, slider, drawer}` and routes to
adjudication rather than guess. This is invariant 1 in action: the parser is a SELECTOR
that **abstains** rather than let an under-specified instruction silently pick a check.

### Misfire rate is the load-bearing 0%

The operational floor would be worthless if it were bought by guessing. It is not:
**held-out misfire rate is 0.0%** — the parser never reduces an instruction to the
*wrong* predicate. A wrong predicate is worse than a Tier-2 route, because it fires a
confident deterministic verdict against the wrong authorized region. The parser is
built to abstain into Tier-2 on any ambiguity, so the 93.3% is a floor you can stand
on, not a coin flip.

---

## What A1 does *not* certify (carried forward)

1. **The floor is CALVIN-specific.** 93.3% is the floor for a curated benchmark. An
   open-vocabulary embodied dataset ("tidy the table") would show a far smaller floor
   and a far larger Tier-2 queue. The claim is existence and size *on this dataset*,
   not universality.
2. **A1 measures instruction → predicate reducibility, not execution correctness.**
   Whether the recorded trace actually *satisfies* the predicate (PASS vs DRIFT vs GAP)
   is the probe's job (`probe_execution_drift.py`), measured against held-out traces.
3. **The set-valued crux is deferred to A2.** CALVIN's predicates check the *terminal
   state*, which collapses the "set of acceptable trajectories" to a near-boolean
   outcome check. Whether that same contract carries the narrator's equality predicate
   is A2, certified by building both adapters against one core.

---

*Header discipline (§5): the overall harness state remains **ASPIRATIONAL** until both
adapters run on one unmodified core with non-zero held-out catch-rate on both
substrates. A1 certified is a precondition, not the terminal state.*
