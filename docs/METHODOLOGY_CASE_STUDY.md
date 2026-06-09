# Case Study: Building a DIY AI-Drivable Tooling Layer on Top of an Operating System

*A methodology walkthrough using the Kali Kimi Interface (KKI) as the worked example.*

---

## 1. The problem this methodology solves

An operating system like Kali Linux already ships ~600 security tools. Each is a mature,
battle-tested binary — `nmap`, `sqlmap`, `gobuster`, `nikto`, `masscan`, `tshark`. The
tools are not the bottleneck. The bottleneck is **orchestration**: deciding which tool to
run, with which arguments, against which target, in what order — and then reading the
output well enough to decide the next move.

That is exactly the kind of judgment an LLM is good at. But you cannot safely hand a shell
to a language model. The gap between "an OS full of powerful binaries" and "an agent that
can drive them" is the gap this methodology fills.

The "DIY model on top of OS methodology" is the discipline of building **thin, verifiable
layers** between the raw operating system and the reasoning model — each layer adding
exactly one guarantee — so that by the time the model issues an instruction, that
instruction is validated, permission-gated, time-bounded, and its output is structured.

KKI is one concrete implementation. This case study generalizes the method so you can
apply it to any OS toolset, not just Kali.

---

## 2. The core insight: treat the OS as a tool substrate, not an environment

The naive approach gives the model a terminal and a system prompt that says "be careful."
This fails for three reasons:

1. **Injection.** The model (or a target's response echoed back to it) can smuggle shell
   metacharacters into a command.
2. **Unbounded blast radius.** A `read-only` recon scan and a `danger-full-access` exploit
   look identical at the shell — both are "just a command."
3. **Unstructured output.** Tool stdout is for humans. An agent that has to re-parse ad-hoc
   text on every turn is brittle and wastes context.

The methodology inverts the relationship. The OS is not the environment the agent lives
in; it is a **substrate of capabilities** the agent reaches through a contract. The
contract is: *the model never names a command, only a tool and a set of typed parameters.*
Everything between that request and the OS is yours to control.

```
            ┌─────────────────────────────────────────────┐
            │   Reasoning model (Kimi / any LLM)            │   "I want nmap on 10.0.0.5"
            └───────────────────────┬─────────────────────┘
                                    │  typed tool call (JSON), never a shell string
            ┌───────────────────────▼─────────────────────┐
   LAYER 4  │   Orchestration loop (orchestrator.py)        │   pick → run → analyze → repeat
            ├───────────────────────────────────────────────┤
   LAYER 3  │   Harness registry (harness_integration.py)   │   ToolSpec: schema + permission
            ├───────────────────────────────────────────────┤
   LAYER 2  │   Safe execution adapter (kali_tools.py)      │   validate, rate-limit, timeout, parse
            ├───────────────────────────────────────────────┤
   LAYER 1  │   Verifiable registry (tool_registry.py)      │   identity: SHA-256, schema, permission
            └───────────────────────┬─────────────────────┘
                                    │  argument array, never shell=True
            ┌───────────────────────▼─────────────────────┐
   LAYER 0  │   Operating system binaries (Kali tools)      │   nmap, sqlmap, gobuster, …
            └───────────────────────────────────────────────┘
```

Each layer is independently testable and adds exactly one property. That separation is the
whole point: when you need to harden injection defense, you touch one layer; when you add a
tool, you touch the registry; when you change how the agent reasons, you touch only the
loop.

---

## 3. The layers, one guarantee at a time

### Layer 0 — The OS binaries (what you do *not* build)

Resist the urge to reimplement. `nmap` has had 25 years of edge-case handling. The
methodology's first rule is **wrap, don't rewrite**. Your code's job is to call the binary
correctly and interpret its output — never to duplicate its logic.

The only thing you assume about Layer 0 is that it might be *missing*. On a real Kali box
all the binaries exist; in a container or a minimal install they may not. So every layer
above must degrade gracefully when a binary is absent rather than crash.

### Layer 1 — Identity and verification (`tool_registry.py`)

Before you can safely run a tool, you must know *what it is*. The registry is the catalog
of record. For each of its 152 tools it holds a `ToolVerif` record:

- the **binary path** and whether it is actually installed (`shutil.which` + common dirs),
- a **SHA-256 hash** of the on-disk binary (integrity — has this been swapped?),
- a **JSON Schema** for its inputs,
- a **permission classification** (`read-only` / `workspace-write` / `danger-full-access`),
- which **output parser** to use.

The methodological move here is to make tool identity *data, not code*. Tools are declared
as tuples in `TOOL_DEFINITIONS` and the registry builds itself from that list. Adding a
tool is adding a row, not writing a function. The registry can then answer questions an
agent needs before it acts: *Is this installed? Is its binary the one I expect? What is it
allowed to do?*

> **Transferable principle:** Give every capability a verifiable identity before you give it
> a trigger. Integrity hashing turns "I ran a tool" into "I ran *this specific* tool," which
> is the difference between an action and an auditable action.

### Layer 2 — Safe execution (`kali_tools.py`, `KaliToolAdapter`)

This is the security-critical heart. It is small on purpose. Every tool invocation passes
through the same gauntlet:

1. **Target validation** (`_validate_target`): reject empty/non-string input and any of the
   `DANGEROUS_CHARS` — ``; & | ` $ ( ) < > \ \n { }`` — that enable command injection.
2. **Argument arrays, never a shell.** Commands are built as `["nmap", "-sS", target]` and
   handed to `subprocess.run`. There is no `shell=True` anywhere, so metacharacters have no
   shell to act on even if validation were bypassed. (Defense in depth: two independent
   barriers.)
3. **Rate limiting** (`_check_rate_limit`): a minimum interval between scans, so a runaway
   loop cannot hammer a network.
4. **Timeouts** (`_execute_tool`): every subprocess is bounded; output is truncated to
   `max_output_size` so one tool cannot blow the context window or fill a disk.
5. **Structured parsing** (`_parse_nmap_output`, `_parse_sqlmap_output`, …): raw stdout is
   turned into a typed `SecurityToolResult` dataclass with a `parsed_output` dict and a
   `.to_json()` method.

The result type matters as much as the safety checks. By returning JSON-everywhere, the
layer guarantees the model upstream always receives the same shape of data regardless of
which tool ran.

> **Transferable principle:** Centralize the dangerous part. Every capability funnels
> through *one* execute method, so the validation, rate limit, timeout, and truncation are
> written once and impossible to forget. A safety check that lives in 40 call sites is a
> safety check that is wrong in at least one of them.

### Layer 3 — The harness contract (`harness_integration.py`, `SecurityToolExecutor`)

Layer 2 knows how to run tools safely. Layer 3 describes them in the vocabulary a
tool-calling model understands. Each tool becomes a `ToolSpec`:

```python
ToolSpec(
    name='nmap_scan',
    description='Execute nmap network scans against targets',
    input_schema={... JSON Schema ...},
    required_permission='danger-full-access',
    handler=self._handle_nmap_scan,
)
```

`execute(tool_name, params)` is the single entry point. It looks up the spec, dispatches to
the handler (which calls into Layer 2), and normalizes the return — `SecurityToolResult`,
plain dict, or error envelope — into a dictionary the loop can serialize. Errors are
*caught and returned as data* (`{"error": ..., "success": False}`), never raised into the
agent loop. An agent should receive a failed tool result it can reason about, not a stack
trace that halts it.

> **Transferable principle:** The boundary the model sees should be a *registry of typed
> capabilities*, each with a description, a schema, and a declared permission. This is also
> exactly the shape modern function-calling / MCP interfaces expect, so the same registry
> drops into any harness.

### Layer 4 — Orchestration (`orchestrator.py`, `KaliKimiOrchestrator`)

The top layer closes the loop:

1. Build a prompt: the target, the task, the *depth* (quick/standard/deep maps to a
   tool-call budget), and the list of available tools with their parameter schemas.
2. Send it to the external Kimi CLI (`_call_kimi`), which returns its decision.
3. **Robustly extract JSON** from the model's prose — three escalating strategies: fenced
   ```` ```json ```` blocks, balanced-brace scanning, then brute-force progressive parsing.
   (Models do not always emit clean JSON; the loop assumes they will not.)
4. Dispatch `action: "tool_call"` through Layer 3; feed a compact result summary back.
5. Repeat until the model returns `action: "complete"` with findings, or the round budget
   is exhausted.
6. Persist the whole session to `<work_dir>/results/<session-id>.json`.

The methodological discipline at this layer is **bounded autonomy**: max rounds, a depth
budget, and a result summary capped in size. The agent is free to reason but cannot run
forever or drown itself in output.

---

## 4. How to replicate this for any OS toolset (the how-to)

The example is Kali, but the recipe is OS-agnostic. To wrap *any* set of system binaries
for an agent:

**Step 1 — Inventory as data.** List your tools as declarative records: name, binary,
category, permission level, input schema, output parser. Do not hardcode them into logic.
KKI uses a list of tuples; a YAML/JSON file works equally well. This single source feeds
discovery, validation, and the agent's tool list.

**Step 2 — Classify by blast radius.** Adopt a small, fixed permission vocabulary. KKI uses
three levels (`read-only`, `workspace-write`, `danger-full-access`). Recon is read-only;
anything that writes, exploits, or scans a network is full-access. The agent — or a human
gate — can then reason about *cost* before running, not just *function*.

**Step 3 — Build the one safe-execute path.** Write a single function that takes a tool
name and typed params and: validates every free-text field, builds an argument array
(never a shell string), enforces a timeout and a rate limit, truncates output, and returns
a structured result. Everything else calls this. Never let a caller build its own
subprocess.

**Step 4 — Parse to a stable shape.** For each tool, write a parser that turns stdout into
the same result dataclass. The agent should never see two different output formats for the
same conceptual outcome.

**Step 5 — Expose a typed registry.** Wrap each tool as a spec (name + description + schema
+ permission + handler) behind one `execute()` method that returns errors as data. This is
your model-facing contract and maps directly onto function-calling / MCP.

**Step 6 — Close the loop with bounds.** A prompt-build → model-call → JSON-extract →
execute → feed-back loop, with a round cap, a depth budget, output-size limits, and session
persistence. Assume the model's output is messy and parse defensively.

**Step 7 — Make it portable.** Resolve external dependencies at runtime instead of
hardcoding paths. KKI's orchestrator locates the Kimi CLI via `--kimi-cli` flag → `KIMI_CLI`
env var → `PATH` → `~/.local/bin/kimi`, defaults its working directory to the repo root,
and fails fast with an actionable message if the reasoning CLI is absent. A DIY model that
only runs on its author's machine is a demo, not a tool.

---

## 5. Security methodology — the guarantees that must not regress

The reason this is a *methodology* and not just an architecture is that the layering exists
to preserve a fixed set of guarantees. When extending the system, these are invariants:

| Guarantee | Where it lives | Why it cannot move up to the model |
|-----------|----------------|-----------------------------------|
| No command injection | `_validate_target` + argument arrays | The model is the *source* of untrusted input; it cannot police itself. |
| No shell interpretation | `subprocess.run` without `shell=True` | Removes the layer where metacharacters become dangerous. |
| Bounded resource use | rate limit + timeout + output truncation | An autonomous loop will otherwise run unbounded. |
| Schema-checked inputs | `validate_input` against JSON Schema | Catches malformed tool calls before they reach a binary. |
| Permission awareness | `Permission` enum / `required_permission` | Lets a human or policy gate full-access actions. |
| Tool integrity | SHA-256 in the registry | Detects a substituted or tampered binary. |
| No leaked artifacts | `.gitignore` blocks `*.json`, `*.pcap`, `*.key`, `shadow`, … | Scan output and credentials must never be committed. |

A sharp edge worth naming: some `command_template`s interpolate free-text fields like
`{flags}`. Validation is strongest on `target`; **any** field that reaches a command line
must be treated as untrusted. Hardening the template fields the way `target` is hardened is
the natural next iteration.

---

## 6. Trade-offs and lessons

- **Thin layers beat a clever monolith.** Each KKI module does one thing. The cost is some
  duplication (the tool catalog is listed in the registry, the menu, *and* the list script);
  the benefit is that any single concern can be changed in isolation. The duplication is a
  known tax — documented so it stays intentional, not accidental.
- **Wrap, don't rewrite.** None of the security logic of `nmap` lives in KKI. The project is
  perhaps 5% of the value of the tools it fronts, and that is correct — the value of the
  layer is *safe accessibility*, not capability.
- **Structured output is a force multiplier.** Forcing every tool through a JSON result type
  is what makes the agent loop tractable. The model reasons over `{"hosts": [...]}` instead
  of re-reading nmap's banner every turn.
- **Degrade, don't crash.** Because Layer 0 may be missing, the higher layers detect
  installed-vs-absent and an integrity check on a missing binary simply reports "not
  installed." The same code runs on a full Kali box and a bare container.
- **Portability is a feature, not an afterthought.** The single biggest barrier to "anyone
  can use this" was hardcoded operator paths in the orchestrator. Runtime resolution of
  external dependencies is what turns a personal script into a shareable tool.

---

## 7. Summary

The methodology is: **place a stack of single-purpose, verifiable layers between an
operating system's raw capabilities and a reasoning model, so that the model gains the OS's
power without its danger.** The OS provides capability; Layer 1 provides identity; Layer 2
provides safety; Layer 3 provides a typed contract; Layer 4 provides bounded autonomy. Each
layer is small, testable, and replaceable, and the security guarantees are invariants that
extension work must preserve rather than erode.

KKI is the worked example, but the recipe — inventory as data, classify by blast radius,
one safe-execute path, parse to a stable shape, expose a typed registry, close the loop with
bounds, and resolve dependencies at runtime — applies to wrapping any operating system's
tooling for an AI agent.
