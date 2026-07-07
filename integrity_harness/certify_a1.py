#!/usr/bin/env python3
"""A1 certification — deterministic-floor existence on the CALVIN instruction set.

A1 (seed assumption): *A non-trivial fraction of the target dataset's instructions
reduce to a deterministically checkable state predicate.* This script certifies A1
empirically against the real CALVIN language-annotation corpus (389 instructions /
34 task classes, pulled into data/calvin_annotations.json) and the 34 deterministic
success predicates (data/calvin_predicates.json).

Two floors are reported, and they are NOT the same number:

  * STRUCTURAL floor  — fraction of instructions whose dataset-assigned task class
    carries a deterministic predicate. This is the ceiling: it answers "does a
    deterministic floor exist at all, and how big could it be." For CALVIN it is
    ~100% by construction (closed-vocabulary curated benchmark).

  * OPERATIONAL floor — fraction of RAW instruction strings that a conservative,
    NO-ML parser can *uniquely* and *correctly* reduce to one predicate, from text
    alone (no dataset label, no scene access, no learned model). This is the honest
    floor: the fraction Tier 1 can stand on WITHOUT a generator in the loop. The
    remainder route to Tier 2 (adjudication). This number is < structural by design;
    the gap is the dataset's genuine under-specification.

Held-out discipline (invariant 6): the corpus is split into TRAIN / HELD-OUT by a
committed hash BEFORE any parser rule is written. Parser rules key on generic
linguistic features only; the reported operational floor is the HELD-OUT number.

Usage:
    python3 integrity_harness/certify_a1.py
    python3 integrity_harness/certify_a1.py --json integrity_harness/reports/a1_result.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

HERE = Path(__file__).resolve().parent
ANNOTATIONS = HERE / "data" / "calvin_annotations.json"
PREDICATES = HERE / "data" / "calvin_predicates.json"

# Frozen experimental variable (invariant 5): the split seed is committed and must
# not be re-rolled to flatter the operational floor.
HELD_OUT_SEED = "A1-calvin-v1"
HELD_OUT_FRACTION = 0.30

COLORS = ("red", "blue", "pink")


# --------------------------------------------------------------------------- #
# Held-out split — computed from a committed seed, before any parser tuning.
# --------------------------------------------------------------------------- #
def split_bucket(instruction: str, task: str) -> str:
    """Deterministic TRAIN / HELDOUT assignment. Stable across runs and machines."""
    digest = hashlib.sha256(f"{HELD_OUT_SEED}|{task}|{instruction}".encode()).hexdigest()
    frac = int(digest[:8], 16) / 0xFFFFFFFF
    return "HELDOUT" if frac < HELD_OUT_FRACTION else "TRAIN"


# --------------------------------------------------------------------------- #
# The deterministic parser (SELECTOR-side, no learned model).
# Returns a *set* of candidate task classes. |set| == 1 => Tier-1 resolvable.
# |set| != 1 (empty or ambiguous) => routes to Tier-2. It ABSTAINS rather than
# guess: emitting the wrong predicate is worse than routing to a human.
# --------------------------------------------------------------------------- #
def _color(text: str) -> Optional[str]:
    found = [c for c in COLORS if re.search(rf"\b{c}\b", text)]
    return found[0] if len(found) == 1 else None


def _direction(text: str) -> Optional[str]:
    left = bool(re.search(r"\bleft\b", text))
    right = bool(re.search(r"\bright\b", text))
    if left and not right:
        return "left"
    if right and not left:
        return "right"
    return None


def parse(raw: str) -> Set[str]:
    """Map a raw instruction to the set of candidate CALVIN task classes."""
    t = raw.lower().strip()
    color = _color(t)
    direction = _direction(t)

    # --- toggles: must be matched BEFORE rotate ("turn on/off") and slider ----
    if re.search(r"\bturn (on|off)\b", t) or re.search(r"\b(switch|button)\b", t):
        onoff = None
        if re.search(r"\bturn on\b", t) or re.search(r"\b(up|upwards)\b", t):
            onoff = "on"
        elif re.search(r"\bturn off\b", t) or re.search(r"\b(down|downwards)\b", t):
            onoff = "off"
        device = None
        if re.search(r"\b(led|green)\b", t) or (re.search(r"\bbutton\b", t) and not re.search(r"\b(light bulb|yellow|switch)\b", t)):
            device = "led"
        elif re.search(r"\b(light bulb|lightbulb|yellow|switch)\b", t):
            device = "lightbulb"
        if device and onoff:
            return {f"turn_{onoff}_{device}"}
        return set()  # abstain: device or polarity under-specified

    # --- rotate: block + turn/rotate + direction (not "turn on/off") ----------
    if re.search(r"\brotate\b", t) or (re.search(r"\bturn\b", t) and color and direction):
        if color and direction:
            return {f"rotate_{color}_block_{direction}"}
        return set()

    # --- slider door: door + left/right ---------------------------------------
    if re.search(r"\bdoor\b", t) and direction:
        return {f"move_slider_{direction}"}

    # --- drawer open/close -----------------------------------------------------
    if re.search(r"\bdrawer\b", t) and not re.search(r"\b(block|object|red|blue|pink)\b", t):
        if re.search(r"\bopen\b", t) or re.search(r"\bpull\b", t):
            return {"open_drawer"}
        if re.search(r"\bclose\b", t) or re.search(r"\bpush\b", t):
            return {"close_drawer"}
        return set()

    # --- push a block into the drawer -----------------------------------------
    if re.search(r"\binto the drawer\b", t):
        return {"push_into_drawer"}

    # --- place / store a held block into a container --------------------------
    if re.search(r"\b(place|put|store)\b", t) and re.search(r"\b(block|object|it)\b", t):
        if re.search(r"\bdrawer\b", t):
            return {"place_in_drawer"}
        if re.search(r"\b(slider|sliding cabinet|cabinet)\b", t):
            return {"place_in_slider"}
        # "put/place the block on top of another block" => stack
        if re.search(r"\bon top of\b", t):
            return {"stack_block"}
        return set()

    # --- stack / unstack -------------------------------------------------------
    if re.search(r"\bunstack\b", t) or re.search(r"\bstacked\b", t) or \
       (re.search(r"\btake off\b", t) and re.search(r"\btop\b", t)) or \
       (re.search(r"\bremove\b", t) and re.search(r"\b(stack|top)\b", t)) or \
       re.search(r"\bcollapse\b", t):
        return {"unstack_block"}
    if re.search(r"\bstack\b", t):
        return {"stack_block"}

    # --- push / slide / sweep a block left|right ------------------------------
    if re.search(r"\b(push|slide|sweep)\b", t) and color and direction:
        return {f"push_{color}_block_{direction}"}

    # --- lift / pick up / grasp a block, surface-qualified ---------------------
    if re.search(r"\b(lift|pick up|grasp|take)\b", t) and color:
        surface = None
        if re.search(r"\b(shelf|sliding cabinet|cabinet|slider)\b", t):
            surface = "slider"
        elif re.search(r"\bdrawer\b", t):
            surface = "drawer"
        elif re.search(r"\btable\b", t):
            surface = "table"
        if surface:
            return {f"lift_{color}_block_{surface}"}
        # surface under-specified ("lift the red block") -> ambiguous over 3 surfaces
        return {f"lift_{color}_block_table",
                f"lift_{color}_block_slider",
                f"lift_{color}_block_drawer"}

    return set()  # no family recognised -> Tier-2


# --------------------------------------------------------------------------- #
# Measurement
# --------------------------------------------------------------------------- #
def certify() -> Dict:
    annotations = json.loads(ANNOTATIONS.read_text())
    predicates = json.loads(PREDICATES.read_text())["predicates"]
    tasks: Dict[str, List[str]] = annotations["tasks"]

    have_predicate = set(predicates.keys())
    all_task_classes = set(tasks.keys())

    total = 0
    structural_checkable = 0
    per_split = {"TRAIN": [], "HELDOUT": []}  # list of (task, raw)

    for task, instrs in tasks.items():
        for raw in instrs:
            total += 1
            if task in have_predicate:
                structural_checkable += 1
            per_split[split_bucket(raw, task)].append((task, raw))

    def eval_split(rows: List[Tuple[str, str]]) -> Dict:
        n = len(rows)
        resolved_correct = resolved_wrong = ambiguous = unresolved = 0
        wrong_examples: List[Dict] = []
        ambig_examples: List[Dict] = []
        for task, raw in rows:
            cand = parse(raw)
            if len(cand) == 1:
                pred = next(iter(cand))
                if pred == task:
                    resolved_correct += 1
                else:
                    resolved_wrong += 1
                    if len(wrong_examples) < 12:
                        wrong_examples.append({"instruction": raw, "label": task, "parsed": pred})
            elif len(cand) == 0:
                unresolved += 1
            else:
                ambiguous += 1
                if len(ambig_examples) < 12:
                    ambig_examples.append({"instruction": raw, "label": task, "candidates": sorted(cand)})
        return {
            "n": n,
            "tier1_resolved_correct": resolved_correct,
            "tier1_resolved_wrong": resolved_wrong,
            "tier2_ambiguous": ambiguous,
            "tier2_unresolved": unresolved,
            "operational_floor": round(resolved_correct / n, 4) if n else 0.0,
            "misfire_rate": round(resolved_wrong / n, 4) if n else 0.0,
            "tier2_route_rate": round((ambiguous + unresolved) / n, 4) if n else 0.0,
            "wrong_examples": wrong_examples,
            "ambiguous_examples": ambig_examples,
        }

    train = eval_split(per_split["TRAIN"])
    heldout = eval_split(per_split["HELDOUT"])

    return {
        "assumption": "A1 (deterministic-floor existence)",
        "dataset": "CALVIN",
        "predicate_set_version": json.loads(PREDICATES.read_text()).get("predicate_set_version", "v1"),
        "held_out_seed": HELD_OUT_SEED,
        "held_out_fraction": HELD_OUT_FRACTION,
        "corpus": {
            "total_instructions": total,
            "task_classes": len(all_task_classes),
            "task_classes_with_deterministic_predicate": len(all_task_classes & have_predicate),
        },
        "structural_floor": {
            "definition": "fraction of instructions whose dataset-assigned task class carries a deterministic predicate",
            "checkable_instructions": structural_checkable,
            "value": round(structural_checkable / total, 4) if total else 0.0,
        },
        "operational_floor_train": train,
        "operational_floor_heldout": heldout,
        "verdict": _verdict(structural_checkable / total if total else 0.0, heldout["operational_floor"]),
    }


def _verdict(structural: float, operational_heldout: float) -> str:
    if operational_heldout <= 0.0:
        return "A1 FAILS: no deterministic floor survives on held-out; harness degenerates to a pure adjudication queue."
    return (
        f"A1 HOLDS: deterministic floor is non-trivial. Structural ceiling {structural:.1%}; "
        f"conservative held-out operational floor {operational_heldout:.1%} of raw instructions "
        f"reduce to a unique deterministic predicate with no learned model in the loop."
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="A1 certification on CALVIN.")
    ap.add_argument("--json", type=Path, help="write full result JSON here")
    args = ap.parse_args()

    result = certify()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(result, indent=2))

    c = result["corpus"]
    s = result["structural_floor"]
    h = result["operational_floor_heldout"]
    tr = result["operational_floor_train"]
    print("=" * 72)
    print("A1 CERTIFICATION — deterministic-floor existence on CALVIN")
    print("=" * 72)
    print(f"corpus: {c['total_instructions']} instructions across "
          f"{c['task_classes']} task classes "
          f"({c['task_classes_with_deterministic_predicate']} carry a deterministic predicate)")
    print(f"held-out split: seed={result['held_out_seed']!r} "
          f"frac={result['held_out_fraction']} "
          f"(train n={tr['n']}, held-out n={h['n']})")
    print("-" * 72)
    print(f"STRUCTURAL floor (ceiling)      : {s['value']:.1%}  "
          f"({s['checkable_instructions']}/{c['total_instructions']})")
    print(f"OPERATIONAL floor (train)       : {tr['operational_floor']:.1%}  "
          f"misfire {tr['misfire_rate']:.1%}  ->Tier2 {tr['tier2_route_rate']:.1%}")
    print(f"OPERATIONAL floor (HELD-OUT)    : {h['operational_floor']:.1%}  "
          f"misfire {h['misfire_rate']:.1%}  ->Tier2 {h['tier2_route_rate']:.1%}")
    print("-" * 72)
    print(result["verdict"])
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
