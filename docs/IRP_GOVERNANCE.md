# KKI IRP Governance Layer

*Mission DH-KKI-IRP-001 — hardening KKI from a capability-mediation wrapper into a
governed, auditable, human-gated tooling layer.*

This document describes the `src/governance/` package: what it enforces, how it maps to the
IRP/MOD-045 task force spec, and — honestly — which parts of the spec are **implemented**,
which are **scoped to a stdlib-equivalent**, and which remain **roadmap**.

## Design philosophy: additive, fail-closed, stdlib-only

The governance layer is **additive**. It does not remove a single existing safety control.
The base adapter's `DANGEROUS_CHARS` blacklist and argument-array execution stay exactly as
they were; the new layer adds *positive allowlist* validation, *permission-as-code*, *human
consent*, *binary attestation*, and an *audit trail* on top. Every gate fails closed: an
unknown tool, an unparseable target, a missing operator, or an unattested binary all
resolve to **deny**, never to "allow by default."

It is also **standard-library only**, matching the repository's core constraint
(`CLAUDE.md`). Where the spec calls for a heavier dependency (Ed25519, WebSockets, GBNF
grammars, Linux capability namespaces), the layer ships the strongest stdlib-only
equivalent and records the heavier option as a documented upgrade path rather than silently
adding a third-party dependency.

## The non-negotiable invariant

> **A `danger-full-access` tool can never reach execution without an approving Mirror_RTC
> consent decision.**

Policy alone cannot grant a DANGER action — `PolicyEngine.evaluate` returns
`REQUIRES_CONSENT`, and only an operator `APPROVE <nonce>` clears the gate. This is enforced
in `GovernedExecutor.execute` and proven by the regression tests in
`tests/test_governance.py` (`TestGovernedExecutorRegression`), which assert the underlying
executor is *never called* when consent is denied, withheld, or when the input fails
validation.

## Agent → module map

| Spec Agent | IRP role | Module | Responsibility |
|---|---|---|---|
| **AG-01 Guardian_Codex** | Policy apex | `policy.py` | Permission-as-code; blast-radius classification; DANGER ⇒ consent. |
| **AG-02 Mnemosyne** | Audit & memory | `audit.py` | Append-only, HMAC hash-chained log; self-referential auditor state. |
| **AG-03 Mirror_RTC** | Human interface | `consent.py` | Per-action `APPROVE <nonce>` gate; default-deny; boundary-consent registry. |
| **AG-04 Loom** | L1/L2 hardening | `validation.py`, `attestation.py` | Allowlist validation; per-invocation binary attestation. |
| **AG-05 Weave** | L3/L4 orchestration | `engine.py` | `GovernedExecutor` — wires the pipeline around `SecurityToolExecutor`. |
| **AG-06 Horizon** | Verification | `tests/test_governance.py` | Injection/escalation/governance-regression coverage. |

The six "agents" are realized as one cohesive package rather than six separate top-level
repos — the responsibilities map cleanly to modules, and a single package is far easier to
test, review, and keep consistent than an org-chart-as-codebase.

## The governed execution pipeline

`GovernedExecutor.execute(tool_name, params)` runs every proposal through:

```
decision-log → policy.evaluate → binary attestation → Mirror_RTC consent → execute → execution-log
                    │                    │                    │                  │
                 DENIED?             unverified?          not APPROVED?      (only if all
                    └── block ──────────┴────────────────────┘               gates cleared)
```

On any block the underlying `SecurityToolExecutor` is never invoked; the call returns a
`GovernedResult` with `allowed=False` and a `denial_reason`, and the block is recorded in
the audit chain.

## Spec task status

### L0–L1 / L2 — registry, identity, safe execution (Loom)

| Task | Status | Notes |
|---|---|---|
| 3.1 Per-invocation attestation | **Implemented** | `attestation.attest_binary`: `realpath` + trusted-dir containment + fresh SHA-256, optional expected-hash compare. |
| 3.1 PATH/symlink hijack detection | **Implemented** | `os.path.realpath` defeats symlink redirection; `commonpath` containment defeats `/usr/bin-evil` prefix tricks. |
| 3.1 Capability-namespace / `kkid` daemon | **Roadmap** | `unshare`/`setcap`/IPC daemon is OS-level work outside a stdlib module; the path-attestation core is the testable first step. |
| 3.1 masscan/tshark under L2 discipline | **Implemented** | `KaliToolAdapter.masscan_scan` (rate ceiling `MAX_MASSCAN_RATE`) and `tshark_capture` (interface allowlist + bounded duration) replace the orchestrator's direct-subprocess wrappers; both inherit `_validate_target`/`_check_rate_limit`/`_execute_tool` and are registered harness tools. |
| 3.2 Strict target allowlist | **Implemented** | `validation.validate_target` uses `ipaddress` (robust IPv4/IPv6/CIDR) + RFC 1123 hostname regex. |
| 3.2 Enumerated safe flags | **Implemented** | `SAFE_FLAGS[tool]` + `validate_flags`; tools without an entry reject all flags (fail closed). Directly closes the `{flags}` sharp edge noted in `CLAUDE.md`. |
| 3.4 Positive validation | **Implemented (additive)** | Allowlist added as the primary gate; the existing `DANGEROUS_CHARS` blacklist is **kept** as defense-in-depth (the spec said "destroy" it — we deliberately did not, to avoid regressing injection tests and to keep two independent barriers). |
| 3.4 Homoglyph / null-byte rejection | **Implemented** | `normalize` does NFKC + null-byte + control-character rejection; the ASCII-only hostname regex rejects non-ASCII confusables. |
| 3.5 Blast-radius budgeting | **Roadmap** | The existing adapter rate-limit/timeout remain; per-round CPU/packet/host budgets are a future `PolicyEngine` extension. |
| 3.6 Parser verification | **Partial** | Results flow through the existing structured `SecurityToolResult`; cross-re-serialization verification is a roadmap item. |

### L3–L4 — harness contract & orchestration (Weave / Guardian_Codex / Mnemosyne / Mirror_RTC)

| Task | Status | Notes |
|---|---|---|
| 3.7 Policy runtime between L3 and L2 | **Implemented + wired** | `GovernedExecutor` is that runtime; `orchestrator.py` now dispatches every tool call through it (`_governed_dispatch`), including the masscan/tshark wrappers via `authorize`. |
| 3.8 Permission-as-code | **Implemented** | `PolicyEngine.evaluate` is a function of context, not an enum read; DANGER ⇒ `REQUIRES_CONSENT`. |
| 3.9 Constrained output (native function-calling / GBNF) | **Roadmap** | Depends on the external Kimi CLI's capabilities; the orchestrator's defensive JSON extraction stays as the stdlib fallback. |
| 3.10 Session provenance | **Implemented (HMAC)** | `AuditLog` chains entries by SHA-256 and tags with HMAC-SHA256 + a self-referential auditor state. Ed25519 + hardware-backed keys = documented upgrade (inject a persisted/HSM key for cross-run non-repudiation). |
| 3.11 Human detach / 30s pause | **Implemented** | `ConsentGate` enforces `APPROVE <nonce>`-or-default-deny with a configurable timeout; the default CLI prompt times out to DENY. |

### Governance & audit (Mnemosyne / Horizon)

| Task | Status | Notes |
|---|---|---|
| 4.1 Non-repudiable audit trail | **Implemented** | Decision/execution/integrity streams in one hash-chained, tamper-evident log. `AuditLog.verify_file(path)` reads a saved chain back and detects payload tampering / chain breaks at the exact entry (keyless SHA-256 chain; inject the key to also re-check HMAC). |
| 4.2 Continuous red-team | **Partial** | `tests/test_governance.py` + `tests/test_orchestrator_governance.py` cover injection, homoglyph, PATH-hijack, hash-mismatch, read-back tamper detection, L2 rate/interface caps, snap-back, and the governance regression; continuous fuzzing is roadmap. |
| 4.3 Boundary-consent pending log | **Implemented** | `ConsentGate.boundary_report()` + `GovernedExecutor.session_report()` capture unauthorized/pending actions at session close. |

## Deliberately *not* done (and why)

- **Did not remove `DANGEROUS_CHARS`.** Keeping the blacklist under the new allowlist is
  strictly safer (two independent barriers) and avoids regressing existing injection tests.
- **Did not add Ed25519 / hardware keys, WebSockets, GBNF, or a namespace daemon.** Each is
  a third-party or OS-level dependency that violates the repo's stdlib-only constraint. The
  stdlib equivalents (HMAC hash-chain, callback consent gate, realpath attestation) deliver
  the same *invariant* and the heavier options are documented upgrade paths.
- **Did not split into six top-level packages.** One reviewable, testable package with clear
  module boundaries serves the same separation of concerns.

## Using it

Library — wrap the existing executor:

```python
from governance.engine import GovernedExecutor

gov = GovernedExecutor(network_scope=["10.0.0.0/8"])   # operator gate via stdin by default
out = gov.execute("nmap_scan", {"target": "10.0.0.5", "scan_type": "syn"})
if out.allowed:
    print(out.result)          # underlying SecurityToolResult dict
else:
    print("blocked:", out.denial_reason)

print(gov.session_report())    # auditor state + boundary-consent at close
gov.save_audit("results/audit-session.json")
```

Custom consent transport (CLI, WebSocket, test stub) — inject a prompt callback:

```python
gov = GovernedExecutor(consent_prompt=lambda req: my_ui.ask(req))   # return "APPROVE <nonce>" / "DENY"
```

Safe governance preview (evaluates a proposed call, executes nothing):

```bash
python3 src/governance/engine.py --tool nmap_scan --target 10.0.0.5 \
    --permission danger-full-access --scope 10.0.0.0/8
```

Orchestrator integration (**wired**): `orchestrator.py` now routes every Kimi-proposed
tool call through a `GovernedExecutor` by default. The action loop's dispatch
(`_governed_dispatch`) sends harness tools through `GovernedExecutor.execute` and the local
masscan/tshark wrappers through `GovernedExecutor.authorize` (gate-only), so neither path
can bypass policy + attestation + consent. Each session writes a Mnemosyne mirror —
`<work_dir>/audit/<session-id>.chain` (the signed chain) and `.pending` (boundary-consent)
— alongside the existing `results/<session-id>.json`. Governance is **always on from the
CLI** — there is no `--ungoverned` flag (the `governed` constructor parameter remains for
in-process test injection only); `--network-scope CIDR` enforces the scope gate. For
danger/workspace-write tools the orchestrator takes a scoped snap-back of
`<work_dir>/workspace` (never the repo/source tree) and rolls it back on failure or denial.
The operator consent prompt is bound to the attested binary SHA-256, and the same single
attestation flows to execution, so there is no consent→exec swap window. In a
non-interactive run the consent gate times out to **DENY**, so a `danger-full-access` tool
fails closed unless an operator is present to approve it.

## Verification

```bash
python3 -m pytest tests/test_governance.py -v   # 41 governance tests
python3 -m pytest tests/ -q                      # full suite — no regressions
python3 src/governance/engine.py --tool nmap_scan --target 10.0.0.5 --permission danger-full-access
```

The regression suite is the proof of the core invariant: with consent denied or withheld, a
`danger-full-access` call returns `allowed=False` and the underlying executor records **zero**
calls.
