# A2 Certification — Does the Conjoining Point Exist?

**State: CERTIFIED — A2 HOLDS (contract holds, zero core strain).**
**Assumption:** *The equality-verifier (narrator) and the membership-verifier
(robotics) share a non-trivial common contract beyond the verdict vocabulary.*
**Method (as mandated):** build both adapters to the §2 contract; measure how much
`verifier_core.py` must change to carry the second adapter. **Zero change ⇒ A2 holds.
Unbounded widening ⇒ A2 fails.**

Reproduce:
```
python3 integrity_harness/adapters/adapter_narrator.py     # equality adapter self-check
python3 integrity_harness/adapters/adapter_robotics.py     # membership adapter self-check
python3 integrity_harness/probes/probe_execution_drift.py  # both on one core, one chain
diff integrity_harness/reports/a2_snapshots/verifier_core.before_narrator.py \
     integrity_harness/verifier_core.py                    # -> empty
```

---

## The measurement: the core did not change

`verifier_core.py` was hashed **before either adapter existed**
(`reports/a2_snapshots/core_before_narrator.sha`). After building the equality adapter
*and then* the membership adapter, the file is **byte-identical**:

```
integrity_harness/verifier_core.py: OK          (sha256 -c against pre-adapter baseline)
diff baseline current  -> (empty)               (no lines changed)
```

**Lines of core changed to carry the second adapter: 0.** A2 holds by the mandate's own
criterion.

### What "holds" means, precisely (the two failure modes the mandate asked to separate)

- **Verdict-vocabulary surface** — did the second adapter force a new verdict symbol or
  fork `{PASS, DRIFT, GAP, ADJUDICATE}`? **No.** One `Verdict` enum, unforked, used by
  both.
- **Predicate-evaluation contract** — did the second adapter force a change to the shape
  the core consumes (`PredicateOutcome(decidable, drift, gap, authority)`)? **No.** Both
  the equality predicate and the membership predicate construct the *same*
  `PredicateOutcome`. The core is a notary over that shape and never learned what a robot
  or a narrator is.

Contract holds on both surfaces. **Quantified strain at the core: zero.**

---

## Why it held — where the set-valued case actually went

The mandate's crux: the narrator's referent is crisp (faithfulness = *equality* to a
discrete record), while the robot's instruction maps to a *set* of acceptable
trajectories (faithfulness = *membership* in an under-specified region). Naively these
need different verifiers. They did not fork the core, for two reasons the code makes
concrete:

1. **Membership was reduced to a terminal-state outcome check.** CALVIN's success
   predicate is over the *end state*, not the trajectory. Any trajectory that reaches the
   licensed terminal region passes — so "membership in the set of acceptable
   trajectories" collapses to the same boolean `(drift, gap)` the equality case produces.
   `adapter_robotics.completed_tasks()` computes the *set of all* fired tasks, and
   `drift = (completed − {instructed}) ≠ ∅`, `gap = instructed ∉ completed`.

2. **The irreducibly set-valued residue was routed, not forced into the core.** When an
   instruction is genuinely under-specified (the A1 Tier-2 residue — e.g. "lift the red
   block", surface unknown), the adapter's SELECTOR-side parser returns >1 candidate
   predicate and the adapter emits `decidable=False → ADJUDICATE`. **The widening the
   set-valued case needs was pre-paid by the fourth verdict symbol.** `ADJUDICATE` was in
   the vocabulary from the start; the membership adapter simply uses it more.

So the equality/membership difference is real, and it is *observable* — but it shows up
as **where each substrate loses decidability**, not as a change to the core:

| | equality (narrator) | membership (robotics) |
|---|---|---|
| predicate kind | near-boolean string equality/membership | terminal-state delta over recorded scene |
| loses decidability when… | restricted marker echoed in a refusal; required fact hedged | instruction is set-valued (surface under-specified) |
| where that residue goes | `ADJUDICATE` (Tier 2) | `ADJUDICATE` (Tier 2) |
| core change required | none | none |

That table **is** the conjoining point: two predicates that break faithfulness
differently, funnelling into one unforked verdict vocabulary over one hash-chained
ledger. Demonstrated by execution (`probe_execution_drift.py`), not asserted from a
diagram.

---

## DONE criteria (§5) — evidence

Emitted by `probe_execution_drift.py` (exit 0):

| Criterion | Result |
|---|---|
| both adapters run against **one unmodified** core | ✅ (SHA identical; 54 entries minted through one `VerifierCore`) |
| verdict vocabulary shared & unforked | ✅ `{PASS, DRIFT, GAP, ADJUDICATE}` |
| provenance chain validates across **both** substrates | ✅ one 54-entry chain, `validate()==True`, substrates `{platformed/narrator, embodied/robotics}` |
| held-out catch-rate non-zero on **both** substrates | ✅ narrator 100% (5/5), robotics 100% (2/2), false-positive 0% |

DRIFT and GAP reported separately, never averaged (invariant 4): narrator
DRIFT 45.8% / GAP 12.5%; robotics DRIFT 26.1% / GAP 26.1% (equal by coincidence, computed
from independent flags — fixture T14 fires *both*, which a single averaged score would
have erased).

---

## Honest limitations — what "REAL" does and does not mean here (do not soften)

The probe prints `CONJOINING POINT STATE: REAL` because all four of the mandate's
operational DONE boxes are checked. That is the mandate's definition, met. But **REAL is
scoped to Round 0's held-out load, and that load is reserved *synthetic fixtures*, not
adversarial real rollouts.** Specifically:

1. **Held-out catch-rate is 100% on synthetic fixtures I authored.** The deterministic
   predicates were not tuned on the held-out slice (they are dataset-derived: CALVIN
   thresholds, BIE markers), so the number is not circular — but the *traces* are
   hand-built, so 100% demonstrates predicate *correctness and consistency*, **not**
   generalisation to real policy behaviour. In-distribution ceilings are
   self-congratulation (invariant 6); this one is held-out but still synthetic.
   **Round 1 must replace fixtures with real CALVIN rollouts and real narrator outputs**
   and re-measure. Expect the catch-rate to drop; that drop is the real signal.

2. **The robotics predicate reads a curated 8-field state log, not raw CALVIN `.npy`.**
   Phase 0 is offline (no 100 GB download). The predicate logic mirrors CALVIN's
   `get_task_info()` but has not been cross-checked against the simulator's own labels on
   real episodes. That cross-check is a Round-1 gate.

3. **`completed_tasks()` treats every non-instructed task-level state change as DRIFT.**
   On real rollouts this may over-flag benign incidental contact. Whether that is
   over-strict is an empirical question for real traces, not this fixture set.

4. **One latent fork risk in the core.** When a trajectory both drifts and gaps, the
   *summary verdict* is DRIFT (both booleans are still recorded in provenance). If a
   future substrate needed "both" as a first-class verdict symbol, the vocabulary would
   fork — that is the boundary where A2 could still fail for substrate #3. It does not
   fail for these two.

**Bottom line:** A2 holds — the conjoining point exists and runs on both substrates
against one unmodified core. The Round-0 evidence is real but its adversarial load is
synthetic; certifying it survives *real* held-out load is Round 1's job. Per §5 the
harness earns the `REAL` label on the mandate's stated criteria; this report records the
exact scope of that word so it is not mistaken for "validated on real robots."
