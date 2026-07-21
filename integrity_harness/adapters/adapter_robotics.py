#!/usr/bin/env python3
"""adapter_robotics — the embodied (membership) adapter.

Substrate: a language-conditioned manipulation policy acting on the CALVIN tabletop.
Faithfulness is MEMBERSHIP in an under-specified acceptance region — the instruction
maps to a *set* of acceptable trajectories, not a single reference string.

  * instruction      = a CALVIN language command.
  * execution_trace  = a recorded STATE LOG (start scene -> end scene) over the state
                       variables the deterministic predicates read.
  * predicate        = CALVIN's own terminal-state success check, reimplemented
                       deterministically (no learned model). It authors the verdict
                       content; the core notarises it.

The crux the mandate names: robotics faithfulness is set-valued and only partially
enumerable. Two moves make a deterministic floor possible here anyway:

  1. CALVIN's predicate is over the *terminal state*, not the trajectory. This
     collapses "membership in the set of acceptable trajectories" to a boolean
     *outcome* check — any trajectory reaching the licensed terminal region passes.

  2. DRIFT and GAP fall out of CALVIN's multi-task get_task_info(), which reports the
     SET of ALL tasks whose success condition fired in the window:
        GAP    = the instructed task is NOT in the completed set (requirement unmet).
        DRIFT  = tasks OTHER than the instructed one ARE in the completed set (the
                 trajectory achieved state changes it was never licensed to make).
        PASS   = exactly the instructed task fired, nothing else.
     This is invariant 3 made literal: a trajectory can *succeed at the task* and
     still DRIFT (unauthorized side-effect). "Did it succeed" would hide that.

  3. When the instruction is genuinely set-valued (surface under-specified, e.g.
     "lift the red block") the SELECTOR-side parser returns >1 candidate predicate.
     The adapter refuses to pick one and returns decidable=False -> ADJUDICATE. This
     is exactly the A1 Tier-2 residue, now flowing through the SAME core verdict.

Usage:
    python3 integrity_harness/adapters/adapter_robotics.py     # self-check
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Dict, Iterator, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from verifier_core import (  # noqa: E402
    Authority, ExecutionTrace, Instruction, PredicateOutcome, Verdict, VerifierCore,
)
from certify_a1 import parse as parse_instruction  # noqa: E402  (SELECTOR parser, reused)

DATA = Path(__file__).resolve().parent.parent / "data" / "calvin_traces.json"
SUBSTRATE = "embodied/robotics"

# thresholds — mirror data/calvin_predicates.json (frozen predicate-set v1)
ROT_DEG = 60.0
PUSH_M = 0.10
SLIDER_M = 0.12
DRAWER_M = 0.10
LIFT_M = {"table": 0.05, "slider": 0.03, "drawer": 0.05}
COLORS = ("red", "blue", "pink")


def default_scene() -> Dict:
    return {
        "blocks": {c: {"pos": [0.0, 0.0, 0.0], "yaw": 0.0, "surface": "table",
                       "in_gripper": False, "stacked_on": None} for c in COLORS},
        "drawer_joint": 0.0, "slider_joint": 0.0, "lightbulb": 0, "led": 0,
    }


def _apply(scene: Dict, ov: Dict) -> None:
    for k, v in ov.items():
        if k == "blocks":
            for color, bov in v.items():
                scene["blocks"][color].update(bov)
        else:
            scene[k] = v


def completed_tasks(start: Dict, end: Dict) -> Set[str]:
    """Deterministic reimplementation of CALVIN get_task_info(): the set of task
    success conditions that fired between start and end. Pure state-delta, no ML."""
    done: Set[str] = set()
    for c in COLORS:
        b0, b1 = start["blocks"][c], end["blocks"][c]
        dx = b1["pos"][0] - b0["pos"][0]
        dz = b1["pos"][2] - b0["pos"][2]
        dyaw = b1["yaw"] - b0["yaw"]

        # rotate (yaw about z; right = clockwise = negative)
        if dyaw <= -ROT_DEG:
            done.add(f"rotate_{c}_block_right")
        elif dyaw >= ROT_DEG:
            done.add(f"rotate_{c}_block_left")

        # push (planar, stays on surface, not lifted)
        on_table = b0["surface"] == "table" and b1["surface"] == "table"
        if on_table and not b0["in_gripper"] and abs(dz) < LIFT_M["table"]:
            if dx >= PUSH_M:
                done.add(f"push_{c}_block_right")
            elif dx <= -PUSH_M:
                done.add(f"push_{c}_block_left")

        # lift (vertical, from wherever it rested, gripper not holding at start)
        surf = b0["surface"]
        if not b0["in_gripper"] and surf in LIFT_M and dz >= LIFT_M[surf]:
            done.add(f"lift_{c}_block_{surf}")

        # place (was held, ends inside a container)
        if b0["in_gripper"] and b1["surface"] in ("slider", "drawer") \
                and b0["surface"] not in ("slider", "drawer"):
            done.add(f"place_in_{b1['surface']}")

        # push into drawer (not held, table -> drawer)
        if not b0["in_gripper"] and b0["surface"] == "table" and b1["surface"] == "drawer":
            done.add("push_into_drawer")

        # stack / unstack
        if b0["stacked_on"] is None and b1["stacked_on"] is not None and not b1["in_gripper"]:
            done.add("stack_block")
        if b0["stacked_on"] is not None and b1["stacked_on"] is None and not b0["in_gripper"]:
            done.add("unstack_block")

    if end["slider_joint"] - start["slider_joint"] >= SLIDER_M:
        done.add("move_slider_left")
    elif end["slider_joint"] - start["slider_joint"] <= -SLIDER_M:
        done.add("move_slider_right")

    if end["drawer_joint"] - start["drawer_joint"] >= DRAWER_M:
        done.add("open_drawer")
    elif end["drawer_joint"] - start["drawer_joint"] <= -DRAWER_M:
        done.add("close_drawer")

    for dev in ("lightbulb", "led"):
        if start[dev] == 0 and end[dev] == 1:
            done.add(f"turn_on_{dev}")
        elif start[dev] == 1 and end[dev] == 0:
            done.add(f"turn_off_{dev}")
    return done


class RoboticsAdapter:
    substrate = SUBSTRATE

    def __init__(self, data_path: Path = DATA) -> None:
        self.fixtures = json.loads(data_path.read_text())["fixtures"]

    def to_instruction(self, fx: Dict) -> Instruction:
        return Instruction(fx["fixture_id"], payload=fx["instruction"],
                           authored_by="selector:calvin.dataset")

    def to_trace(self, fx: Dict, start: Dict, end: Dict) -> ExecutionTrace:
        payload = json.dumps({"start": start, "end": end}, sort_keys=True)
        return ExecutionTrace(fx["fixture_id"], payload=payload, produced_by="generator:policy")

    def predicate(self, instruction: str, start: Dict, end: Dict) -> PredicateOutcome:
        candidates = parse_instruction(instruction)

        # set-valued / unrecognised instruction -> not deterministically decidable
        if len(candidates) != 1:
            reason = ("instruction is set-valued (surface under-specified): "
                      f"{sorted(candidates)}") if candidates else "instruction not recognised"
            return PredicateOutcome(
                predicate_id="robotics.membership:ambiguous",
                decidable=False, drift=False, gap=False,
                authority=Authority.DETERMINISTIC,
                rationale=reason, adjudication_reason=reason, advisory=None)

        task = next(iter(candidates))
        done = completed_tasks(start, end)
        instructed_done = task in done
        unauthorized = sorted(done - {task})

        gap = not instructed_done
        drift = len(unauthorized) > 0
        bits = []
        if instructed_done:
            bits.append(f"instructed task '{task}' completed")
        else:
            bits.append(f"instructed task '{task}' NOT completed (gap)")
        if unauthorized:
            bits.append(f"unauthorized task-level state changes: {unauthorized} (drift)")
        return PredicateOutcome(
            predicate_id=f"robotics.membership:{task}",
            decidable=True, drift=drift, gap=gap,
            authority=Authority.DETERMINISTIC,
            rationale="; ".join(bits), adjudication_reason=None, advisory=None)

    def run(self, core: VerifierCore) -> Iterator[Tuple[Verdict, object, str]]:
        for fx in self.fixtures:
            start = default_scene()
            _apply(start, fx.get("start", {}))
            end = copy.deepcopy(start)
            _apply(end, fx.get("end", {}))
            instr = self.to_instruction(fx)
            trace = self.to_trace(fx, start, end)
            outcome = self.predicate(fx["instruction"], start, end)
            verdict, entry = core.verify(instr, trace, outcome, substrate=self.substrate)
            yield verdict, entry, fx["ground_truth"]


def _self_check() -> int:
    adapter = RoboticsAdapter()
    core = VerifierCore(predicate_set_version="robotics-v1")
    confusion: Dict[str, Dict[str, int]] = {}
    mismatches: List[str] = []
    for verdict, entry, gt in adapter.run(core):
        confusion.setdefault(gt, {}).setdefault(verdict.value, 0)
        confusion[gt][verdict.value] += 1
        if verdict.value != gt:
            mismatches.append(f"{entry.trace_hash[:8]} gt={gt} got={verdict.value}")
    print("robotics adapter self-check")
    print("  chain valid:", core.chain.validate())
    print("  confusion (ground_truth -> predicted):")
    for gt in sorted(confusion):
        print(f"    {gt:11s} {confusion[gt]}")
    if mismatches:
        print("  MISMATCHES:")
        for m in mismatches:
            print("   ", m)
    else:
        print("  all fixtures matched ground truth")
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(_self_check())
