# KKI IRP Governance Documentation

**Kali Kimi Interface — Sovereign Tooling Layer**

- **Version:** 2.1
- **Compliance:** IRP Governance Stack + MOD-045 Behavioral Stack
- **Classification:** Defensive Security Architecture — stdlib-only

> **Accuracy note:** Every API signature, path, count, and code snippet in this document is
> reconciled against the implementation and the test suite as of this revision. Where a
> capability is aspirational rather than shipped, it is labelled **Roadmap**.

---

## 1. Executive Summary

The Kali Kimi Interface (KKI) is a sovereign tooling layer that places a governance stack
between an operating system's raw capabilities and a reasoning model. The system enforces a
single invariant:

> No `danger-full-access` tool may reach `subprocess.run` without passing through
> `GovernedExecutor._gate()` → `PolicyEngine.evaluate()` → per-invocation
> `attest_binary()` → `ConsentGate.request()` → operator `APPROVE <nonce>`.

This documentation covers the architecture, operational procedures, compliance matrix, and
upgrade paths for deployment.

---

## 2. Architecture Overview

### 2.1 The Layered Stack

```
┌─────────────────────────────────────────────┐
│ L4: Orchestration Loop (orchestrator.py)      │  Prompt → Model → JSON → Execute → Repeat
├─────────────────────────────────────────────┤
│ L3: Harness Registry (harness_integration.py) │  ToolSpec: schema + permission + handler
├─────────────────────────────────────────────┤
│ L2: Safe Execution (src/kali_tools.py)        │  validate → rate-limit → timeout → parse
├─────────────────────────────────────────────┤
│ L1: Identity & Verification (attestation.py)  │  realpath + SHA-256 + trusted-directory
├─────────────────────────────────────────────┤
│ L0: OS Binaries (Kali tools)                  │  nmap, sqlmap, masscan, tshark, gobuster...
└─────────────────────────────────────────────┘
         ▲
         │  Governance Layer (src/governance/)
         │
┌─────────────────────────────────────────────┐
│ Engine (engine.py)                          │  GovernedExecutor: wires all gates + preview
├─────────────────────────────────────────────┤
│ Policy Apex (policy.py)                      │  Permission-as-code; blast-radius evaluation
├─────────────────────────────────────────────┤
│ Consent Gate (consent.py)                   │  Mirror_RTC: per-action APPROVE <nonce>
├─────────────────────────────────────────────┤
│ Audit & Memory (audit.py)                   │  Mnemosyne: append-only HMAC hash chain
├─────────────────────────────────────────────┤
│ Validation (validation.py)                  │  Positive allowlist; NFKC; homoglyph rejection
├─────────────────────────────────────────────┤
│ Attestation (attestation.py)                │  Per-invocation binary identity verification
└─────────────────────────────────────────────┘
```

> `orchestrator.py` lives at the **repository root** (it adds `src/` to `sys.path` at
> runtime). Everything else above lives under `src/`.

### 2.2 Design Principles

- **Additive Hardening** — Every new gate is added alongside existing protections. The
  `DANGEROUS_CHARS` blacklist remains as defense-in-depth beneath the positive allowlist.
- **Fail-Closed** — If any gate fails (missing binary, denied consent, validation error),
  execution aborts at the earliest possible layer.
- **No Shell Interpretation** — All tool invocations use `subprocess.run` with argument
  arrays. `shell=True` is prohibited at every layer.
- **Audit Everything** — Every decision, denial, and execution is logged to a
  tamper-evident chain.
- **stdlib-Only** — No third-party dependencies for the governance core. Upgrade paths
  (Ed25519, namespaces) are optional and explicitly labelled Roadmap.

---

## 3. Layer Documentation

### 3.1 L0 — OS Binaries (What You Do Not Build)

KKI does not reimplement security tools. `nmap` has 25+ years of edge-case handling. The
methodology's rule is **wrap, don't rewrite**.

**Assumption:** Binaries may be missing. All layers above must degrade gracefully.

**Trusted binary directories** (`attestation.TRUSTED_DIRS`): `/usr/bin`, `/usr/local/bin`,
`/usr/sbin`, `/bin`, `/sbin` and the like — verified by realpath containment, not string
prefix.

### 3.2 L1 — Identity & Verification (`src/governance/attestation.py`)

**Purpose:** Know exactly what binary is about to execute.

Per-invocation checks:

- **Resolution** — `shutil.which` → `os.path.realpath`, with trusted-directory containment
  via `os.path.commonpath` (defeats `/usr/bin-evil` prefix tricks).
- **Integrity** — fresh streaming SHA-256 of the on-disk binary.
- **Symlink/redirection detection** — realpath resolves to the real file; if the resolved
  path is outside the trusted set, `verified` is `False`.
- **TOCTOU protection** — attestation is computed **once per `_gate()` call**; the same
  `Attestation` object is surfaced in the consent prompt and used by the execution path —
  there is no re-attestation between consent and execution.

**API:**

```python
@dataclass
class Attestation:
    name: str
    resolved_path: Optional[str]
    real_path: Optional[str]
    sha256: Optional[str]
    installed: bool
    in_trusted_dir: bool
    hash_matches: Optional[bool]   # None when no expected hash was supplied
    verified: bool                 # installed AND trusted AND (hash_matches is not False)
    reason: str

def attest_binary(name: str, expected_sha256: Optional[str] = None) -> Attestation
```

### 3.3 L2 — Safe Execution (`src/kali_tools.py`)

**Purpose:** Centralize dangerous execution paths through a single validated gateway.

The adapter is a single class, **`KaliToolAdapter`**, exposing one method per wrapped tool
(`nmap_scan`, `sqlmap_scan`, `gobuster_scan`, `dirb_scan`, `nikto_scan`, `hydra_scan`,
`quick_recon`, `masscan_scan`, `tshark_capture`). Every method runs the same gauntlet:

1. **Target validation** — `_validate_target` rejects empty/non-string input and any
   `DANGEROUS_CHARS` (`` ; & | ` $ ( ) < > \ \n { } ``).
2. **Rate limiting** — `_check_rate_limit` enforces a minimum interval between scans
   (`self._rate_limit_seconds = 1`).
3. **Timeout** — every subprocess is bounded (`self.timeout`, default **300s**;
   per-call override supported).
4. **Output truncation** — `max_output_size` (default 50 000) prevents context-window
   flooding or disk exhaustion.
5. **Structured parsing** — raw stdout becomes a typed `SecurityToolResult` with
   `.to_dict()` / `.to_json()`.

| Method (`KaliToolAdapter`) | Typical permission | Tool-specific control |
|---|---|---|
| `nmap_scan` | `danger-full-access` | structured output parsing |
| `sqlmap_scan` | `danger-full-access` | non-interactive flags |
| `masscan_scan` | `danger-full-access` | `MAX_MASSCAN_RATE = 100000` pps hard ceiling |
| `tshark_capture` | `danger-full-access` | `ALLOWED_TSHARK_INTERFACES` allowlist + duration bound (1–300s) |
| `gobuster_scan` / `dirb_scan` | `workspace-write` | wordlist path validation |

> Permission is authoritative on the **harness `ToolSpec`** (§3.4), not hard-coded in the
> adapter. masscan/tshark are first-class harness tools — there is no direct-`subprocess`
> wrapper path anywhere in the orchestrator.

**No-shell rule:**

```python
# CORRECT
subprocess.run(["nmap", "-sS", target], timeout=300, capture_output=True)

# PROHIBITED
subprocess.run(f"nmap -sS {target}", shell=True, timeout=300)
```

### 3.4 L3 — Harness Contract (`src/harness_integration.py`)

**Purpose:** Describe tools in the vocabulary a model understands.

```python
@dataclass
class ToolSpec:
    name: str                    # Model-facing name (e.g. "nmap_scan")
    description: str             # Natural-language capability description
    input_schema: dict           # JSON Schema for parameter validation
    required_permission: str     # read-only | workspace-write | danger-full-access
    handler: Callable            # dispatch into the KaliToolAdapter method
```

Execution flow: `execute(tool_name, params)` → spec lookup → handler dispatch → L2 method.
masscan/tshark are registered as `masscan_quick` and `tshark_capture` (the names the model
already emits).

### 3.5 L4 — Orchestration (`orchestrator.py`)

**Purpose:** Close the loop — prompt → model → JSON → execute → feedback → repeat.

**Bounded autonomy:** `--max-rounds` caps tool invocations per session; `--depth`
(`quick` / `standard` / `deep`) selects a budget; `max_output_size` truncates before
context overflow.

**Governance wiring** — the constructor builds the governed pipeline:

```python
# Production path (default)
orch = KaliKimiOrchestrator(work_dir="./sessions")   # governed=True by default

# Test injection only (never exposed on the CLI)
orch = KaliKimiOrchestrator(governed=False)          # pytest use
```

Internally `self.executor` is a `GovernedExecutor` and `self.governed` is
`isinstance(self.executor, GovernedExecutor)`. **There is no `--ungoverned` CLI flag** — the
`governed` parameter exists solely for in-process test injection.

**Session artifacts:**

- `results/<session-id>.json` — structured findings
- `audit/<session-id>.chain` — Mnemosyne tamper-evident log
- `audit/<session-id>.pending` — boundary-consent queue at session close

**Snap-Back Recovery** — for `danger-full-access` and `workspace-write` tools, the
orchestrator snapshots a **scoped** artifacts directory before execution and rolls back on
failure or consent denial:

```python
# Before execution (scoped to <work_dir>/workspace)
snap = self._create_snap(self._workspace_dir())   # returns None for unsafe targets

# On failure or denial
self._restore_snap(self._workspace_dir(), snap)

# On success
self._delete_snap(snap)
```

**Scope guard:** `_create_snap` refuses to snapshot the work-dir root or any directory
containing a `.git` checkout — it will **never** copy the repository/source tree or audit
chains. In the current toolset most output is stdout-captured, so snap-back is a safety net
for file-writing tools rather than a hot path. Each snap event (`snap_created`,
`snap_restored`, `snap_deleted`) is written to the audit chain via `log_integrity`.

---

## 4. Governance Layer Deep Dive

### 4.1 Validation (`src/governance/validation.py`)

**Positive-allowlist philosophy:** reject by default, permit only known-good patterns.

Pipeline (`validate_target` / `validate_url` / `validate_flags`):

1. **NFKC normalization** (`normalize`) — defeats homoglyph attacks.
2. **Null-byte and metacharacter rejection.**
3. **Length bounds** — prevents ReDoS.
4. **Pattern match** — IPv4/IPv6/CIDR via the `ipaddress` module; RFC 1123 hostnames.
5. **Flag validation** — each tool maps to a `SAFE_FLAGS` allowlist; any flag not in the
   set raises `PolicyViolation` before the argument array is built.

### 4.2 Policy Engine (`src/governance/policy.py`)

**Permission-as-code.** The engine receives the permission classification from the harness
`ToolSpec` and decides at which gate the call lands:

```python
def evaluate(self, tool_name: str, permission: str, params: Dict[str, Any]) -> PolicyDecision:
    # Content validation runs FIRST (raises PolicyViolation on bad input).
    # Optional network-scope check against NETWORK_SCOPE_ALLOWLIST.
    # Returns a PolicyDecision carrying blast_radius + authorization.
```

```python
@dataclass
class PolicyDecision:
    tool: str
    blast_radius: BlastRadius          # LOW | MEDIUM | HIGH
    authorization: Authorization       # GRANTED | REQUIRES_CONSENT | DENIED
    reasons: List[str]
    normalized_params: Dict[str, Any]
```

**Blast-radius classification:**

- **`read-only`** → `GRANTED` — reconnaissance, no state mutation.
- **`workspace-write`** → `GRANTED` (with snap-back) — file/report writes under the work dir.
- **`danger-full-access`** → `REQUIRES_CONSENT` — network scanning, exploitation, capture.

### 4.3 Consent Gate — Mirror_RTC (`src/governance/consent.py`)

For `danger-full-access`, the operator is the non-negotiable apex.

Challenge/response (default `ConsentGate(timeout=30.0)`):

```
[CONSENT] Tool: nmap
TARGET: 10.0.0.1
BLAST RADIUS: high
EST IMPACT: nmap_scan against 10.0.0.1 [sha256:a1b2c3d4e5f6a7b8]
NONCE: 8f4e2b1c...
Default on 30s timeout: DENY
> APPROVE 8f4e2b1c...
```

Rules:

- Default on timeout, wrong nonce, no response, or **no available operator** → **DENY**.
- Nonce must match exactly (prevents replay).
- The **attested binary SHA-256 is bound into the prompt** (`EST IMPACT`), and that same
  single attestation flows to execution — closing the consent→exec TOCTOU window.

Transport is pluggable (`prompt_fn`). Default is a stdin prompt with a POSIX-`select`
timeout. Production upgrade: WebSocket / hardware token / out-of-band (Roadmap).

### 4.4 Audit & Memory — Mnemosyne (`src/governance/audit.py`)

**Append-only hash chain.** Each entry links to the previous by hash and carries an HMAC
tag:

```json
{
  "seq": 4,
  "timestamp": "2026-06-10T02:01:00Z",
  "category": "execution",
  "payload": { "...": "..." },
  "prev_hash": "sha256_of_previous_entry",
  "entry_hash": "sha256_of_this_entry_body",
  "hmac": "hmac_sha256_over_entry_hash"
}
```

**API:**

```python
log.append(category, payload)        # also: log_decision(...), log_integrity(...)
log.verify() -> Tuple[bool, Optional[int]]          # in-memory (ok, first_bad_seq)
AuditLog.verify_file(path, key=None) \
    -> Tuple[bool, Optional[int], str]              # read-back (ok, first_bad_seq, reason)
log.save(path)                                       # writes {session_id, auditor_state, entries}
log.auditor_state()                                  # tip hash + chain_valid summary
```

**Tamper detection (`verify_file`):** re-walks the **keyless** SHA-256 chain, recomputing
each `entry_hash` from its body and checking `prev_hash` linkage. It detects:

- single-bit flip in a payload → `(False, <seq>, "hash_mismatch")`
- deleted/reordered entry → `(False, <seq>, "chain_break")`

The HMAC key is **ephemeral and not persisted** (documented upgrade path), so cross-process
HMAC verification is opt-in: pass the original `key` to also check the `hmac` tag
(`"hmac_mismatch"`). The saved manifest embeds `auditor_state` (the chain tip + validity at
save time) rather than a separate periodic checkpoint entry.

### 4.5 Engine (`src/governance/engine.py`)

The pipeline (`GovernedExecutor._gate`):

```
1. Content + permission evaluation ............ policy.evaluate(tool, permission, params)
2. Per-invocation binary attestation (ONCE) ... attest_binary(...)
3. Consent — if REQUIRES_CONSENT .............. consent.request(...) (hash bound in prompt)
4. Execution — via the base executor .......... SecurityToolExecutor.execute(...)
5. Audit logging — decision / execution / integrity
```

(Snap-back, step "0/6", is applied by the **orchestrator** around the gate, since it owns
the work dir — see §3.5.)

**Preview mode** — a read-only pre-flight with no consent and no execution:

```python
pre: ExecutionPreCheck = executor.preview("nmap_scan", {"target": "10.0.0.1"})
# fields: tool_name, permission_level, requires_consent, network_scope_ok,
#         target_normalized, safe_flags, rejected_flags, estimated_blast_radius
```

---

## 5. API Reference

### 5.1 Public API Surface (`src/governance/__init__.py`)

```python
from .validation import (
    validate_target, validate_url, validate_flags, normalize, SAFE_FLAGS, PolicyViolation,
)
from .attestation import attest_binary, Attestation, TRUSTED_DIRS
from .consent import ConsentGate, ConsentDecision, ConsentRequest, ConsentResult
from .audit import AuditLog, AuditEntry
from .policy import PolicyEngine, PolicyDecision, BlastRadius, Authorization
from .engine import GovernedExecutor, GovernedResult
# ExecutionPreCheck is importable from governance.engine.
```

### 5.2 Orchestrator Integration

```python
from orchestrator import KaliKimiOrchestrator   # repo root

orch = KaliKimiOrchestrator(work_dir="./sessions")   # governed=True by default

# The constructor internally builds, roughly:
# self.executor = GovernedExecutor(
#     executor=SecurityToolExecutor(),
#     policy=PolicyEngine(network_scope=[...]),
#     consent=ConsentGate(),
#     audit=AuditLog(session_id=self.session_id),
# )
# self.governed = isinstance(self.executor, GovernedExecutor)
```

### 5.3 Test Injection

```python
# pytest fixture — inject a GovernedExecutor with stubbed collaborators
@pytest.fixture
def governed_executor():
    return GovernedExecutor(
        executor=FakeExecutor(),
        policy=PolicyEngine(),
        consent=ConsentGate(prompt_fn=lambda req, t: None),   # no operator -> DENY
        audit=AuditLog(session_id="test"),
    )
```

---

## 6. Compliance Matrix

### 6.1 MOD-045 Behavioral Stack

| Requirement | Implementation | Verifying test |
|---|---|---|
| CF-3 halts on format regardless of source | JSON extraction untouched; malformed input never reaches governance | `test_orchestrator_preserves_json_extraction_on_governance_error` |
| RTC gate mandatory before danger | Every `danger-full-access` path hits `ConsentGate.request()` | `test_danger_blocked_when_consent_denied`, `test_orchestrator_blocks_local_wrapper_without_consent` |
| Per-action operator authorization | `APPROVE <nonce>`, default-deny on timeout / wrong nonce / no operator | `test_danger_blocked_when_no_operator`, `test_no_response_not_approved`, `test_wrong_nonce_denied` |
| Snap-back candidates logged | `snap_created` / `snap_restored` integrity entries; rollback on failure | `test_snap_back_restores_on_failure`, `test_snap_refuses_repo_root_and_vcs` |
| Audit tamper detection | `verify_file()` pinpoints a single-entry flip | `test_verify_file_detects_single_entry_tamper`, `test_tamper_detected` |
| Integrity artifacts flag process gaps | `preview()` / `ExecutionPreCheck` exposes rejected flags + scope status | `test_disallowed_flag_rejected` |
| Content then process validity | validation runs inside `policy.evaluate()` before the permission gate | `test_injection_denied_before_execution` |
| Boundary-consent pending at session close | unresolved queue flushed to `audit/<id>.pending` | `test_boundary_report` |
| Attestation TOCTOU closed | single attest per `_gate()`; hash bound into consent prompt | `test_trusted_binary_verifies`, `test_danger_runs_only_after_approval` |
| No regression | full pytest suite | **103 passed, 3 skipped, 0 failed** |

### 6.2 IRP Governance Framework

| IRP Component | KKI Implementation | Status |
|---|---|---|
| Guardian_Codex | `PolicyEngine` — policy-as-code, permission classification + blast radius | ✅ Implemented |
| Mnemosyne | `AuditLog` — append-only HMAC chain; `auditor_state()` tip summary | ✅ Implemented |
| Mirror_RTC | `ConsentGate` — per-action operator authorization, default-deny | ✅ Implemented |
| Hue & Logic philosophy | fail-closed, additive hardening, operator-as-apex | ✅ Architectural |
| RLM orchestration | `KaliKimiOrchestrator` — bounded autonomy, depth budgets, round caps | ✅ Implemented |
| CRTP protocol | `preview()` / `execute()` separation exists; multi-agent simulation | ⏳ Roadmap |

---

## 7. Operational Procedures

### 7.1 Starting a Governed Session

```bash
# Standard session — governance active, consent prompts enabled
python3 orchestrator.py --target 10.0.0.0/8 --depth standard

# With explicit network scope (repeatable flag — NOT comma-separated)
python3 orchestrator.py --target 10.0.0.5 \
    --network-scope 10.0.0.0/8 --network-scope 192.168.0.0/16
```

> The Kimi reasoning CLI must be resolvable (`--kimi-cli` / `KIMI_CLI` / `PATH` /
> `~/.local/bin/kimi`); the orchestrator fails fast with exit code 1 if it is missing.

### 7.2 Responding to Consent Prompts

```
[CONSENT] Tool: nmap
TARGET: 10.0.0.1
BLAST RADIUS: high
EST IMPACT: nmap_scan against 10.0.0.1 [sha256:a1b2c3d4e5f6a7b8]
NONCE: 7d3f...9a2b
Default on 30s timeout: DENY
> APPROVE 7d3f...9a2b
[OK] Executing...

# Deny / timeout / wrong nonce all resolve to:
[BLOCKED] Consent denied. Tool execution aborted.
```

### 7.3 Audit Chain Verification

```python
from governance.audit import AuditLog

ok, first_bad_seq, reason = AuditLog.verify_file("./sessions/audit/sess_abc123.chain")
if not ok:
    raise SystemExit(f"TAMPER DETECTED at entry {first_bad_seq}: {reason}")
print("Audit chain verified.")
```

### 7.4 Emergency Procedures

**Governance failure mid-session** — the orchestrator aborts the current tool call,
snap-back restores the workspace, the audit chain logs the failure, and the session is safe
to inspect read-only.

**Binary tampering detected** — `Attestation.verified == False` blocks the call; the gate
records the attestation reason (expected vs. actual). Investigate before re-running.

---

## 8. Security Guarantees & Invariants

### 8.1 Guaranteed Properties

| Guarantee | Enforcement | Not bypassable by |
|---|---|---|
| No command injection | positive allowlist + `DANGEROUS_CHARS` blacklist + argument arrays | prompt injection, target echo |
| No shell interpretation | `subprocess.run(args, shell=False)` everywhere | metacharacters in any parameter |
| Bounded resources | rate limit + timeout + output truncation | runaway loops, context flooding |
| Schema-checked inputs | JSON Schema per `ToolSpec` | malformed-but-typed calls |
| Permission awareness | policy-as-code with `danger-full-access` gate | model reasoning / social engineering |
| Tool integrity | per-invocation SHA-256 + realpath containment | PATH hijack, symlink, binary swap |
| Non-repudiable audit | SHA-256 hash chain (+ optional HMAC) | log deletion, entry edit, reorder |
| Operator sovereignty | `ConsentGate` nonce + default-deny | automated override, timed bypass |

### 8.2 Known Limitations (Honest Posture)

| Limitation | Risk | Mitigation | Upgrade path |
|---|---|---|---|
| HMAC key is ephemeral / not persisted | Medium | file read-back verifies the keyless chain; in-process verify checks HMAC | Ed25519 asymmetric signing + HSM |
| No Linux namespace sandboxing | Medium | process runs as orchestrator UID | `unshare()` / `setcap()` capability dropping |
| No grammar-constrained model output | Low | defensive JSON extraction + schema validation | native forced tool-use API |
| masscan/tshark filter validation is allowlist-level | Low | interface allowlist + duration/rate bounds + metachar rejection | full BPF/eBPF validation |
| Snap-back scoped to `<work_dir>/workspace` | Low | repo-root / `.git` guard; most output is stdout-captured | filesystem (ZFS/Btrfs) snapshots |
| CRTP multi-agent simulation | n/a | `preview()`/`execute()` separation in place | full multi-agent orchestration |

---

## 9. Testing & Verification

### 9.1 Test Suite Structure

```
tests/
├── test_governance.py              # 43 tests — validation, policy, consent, audit, attestation, verify_file
├── test_kali_tools.py              # 29 tests — L2 adapters, timeout, rate limit, parsing (3 localhost-integration skip in a bare container)
├── test_orchestrator_governance.py # 11 tests — wiring, snap-back, CLI rejection, L2 caps, tamper detection
├── test_tool_registry.py           # 23 tests — registry construction, hashing, verification
└── test_kali_integration.py        #  5 tests — live-binary acceptance checks (2 self-skip without /usr/bin/nmap)
```

Total in a bare container: **106 passed, 5 skipped, 0 failed.** The 5 skips are 3 localhost
`nmap` scans in `test_kali_tools.py` plus the 2 binary-gated checks in
`test_kali_integration.py`, which only run where the tool is installed.

**Validated on real hardware — PurpBox (Kali 6.18.3, Python 3.13.11):** all five
`test_kali_integration.py` checks pass (the two container-skips execute), including the
privileged syn-scan path under `sudo`. Confirmed live: `attest_binary("nmap").sha256`
equals `sha256sum /usr/bin/nmap` with `verified=True`; the consent gate fails closed on
no-response (`allowed=False`, nmap never runs); the attested hash is bound into the consent
prompt (`est_impact: "… [sha256:…]"`); and a single-byte flip in the persisted audit chain
is caught at the exact entry.

### 9.2 Running the Suite

```bash
pip3 install pytest                                   # not bundled
python3 -m pytest tests/ -v                           # full suite
python3 -m pytest tests/test_governance.py tests/test_orchestrator_governance.py -v
```

### 9.3 Red-Team Spot Checks

```bash
# No CLI bypass — argparse must reject --ungoverned
python3 -c "
import subprocess, sys
p = subprocess.run([sys.executable, 'orchestrator.py', '--target', '1.1.1.1', '--ungoverned'],
                   capture_output=True, text=True)
assert p.returncode != 0 and 'unrecognized arguments' in p.stderr, 'CLI bypass present!'
print('No CLI bypass: PASS')
"

# Audit tamper detection — flip a payload byte and confirm verify_file flags it
python3 -c "
import sys, json, tempfile, os; sys.path.insert(0, 'src')
from governance.audit import AuditLog
log = AuditLog(session_id='rt'); [log.append('decision', {'i': i}) for i in range(4)]
p = log.save(os.path.join(tempfile.mkdtemp(), 'c.json'))
ok, _, _ = AuditLog.verify_file(p); assert ok, 'clean chain failed!'
d = json.load(open(p)); d['entries'][1]['payload']['i'] = 999; json.dump(d, open(p, 'w'))
ok, seq, reason = AuditLog.verify_file(p)
assert not ok and seq == 1, 'tamper detection failed!'
print(f'Tamper detection: PASS ({reason} at seq {seq})')
"
```

---

## 10. Upgrade Paths

### 10.1 Production Hardening Roadmap

| Phase | Feature | Dependency |
|---|---|---|
| 2.2 | Ed25519 audit signing | `cryptography` / `pynacl` |
| 2.3 | Hardware-token consent (FIDO2/YubiKey) | `fido2` |
| 2.4 | Linux capability sandboxing | `unshare`, `setcap`, `seccomp` |
| 2.5 | Network-namespace isolation | `ip netns`, veth pairs |
| 2.6 | Grammar-constrained model output | provider API support |
| 3.0 | Distributed multi-node governance | consensus for policy |

### 10.2 Migration from HMAC to Ed25519

```python
# Current (stdlib-only): keyless chain read-back + in-process HMAC
ok, seq, reason = AuditLog.verify_file(path)            # keyless
ok, seq, reason = AuditLog.verify_file(path, key=k)     # + HMAC

# Upgrade (requires cryptography): persist a public key, verify signatures cross-process
# verify_file() would call public_key.verify() in place of hmac.compare_digest().
```

---

## 11. Repository Structure (governance-relevant)

```
kali-kimi-interface/
├── CLAUDE.md                       # Repo conventions (stdlib-only, no regression)
├── orchestrator.py                 # L4: bounded autonomy loop (repo root)
├── docs/
│   └── IRP_GOVERNANCE.md           # This document
├── src/
│   ├── harness_integration.py      # L3: typed tool registry
│   ├── kali_tools.py               # L2: KaliToolAdapter safe-execution methods
│   ├── tool_registry.py            # Verifiable tool registry (SHA-256, schemas)
│   ├── network_mapper.py           # WiFi/Ethernet discovery
│   └── governance/                 # IRP governance stack
│       ├── __init__.py
│       ├── engine.py               # GovernedExecutor: pipeline + preview
│       ├── policy.py               # Permission-as-code, blast radius
│       ├── consent.py              # Mirror_RTC: operator consent gate
│       ├── audit.py                # Mnemosyne: tamper-evident chain
│       ├── validation.py           # Positive allowlist, NFKC, homoglyphs
│       └── attestation.py          # Per-invocation binary identity
├── tests/
│   ├── test_governance.py          # 43 governance unit tests
│   ├── test_kali_tools.py          # 29 L2 adapter tests
│   ├── test_orchestrator_governance.py # 11 integration tests
│   └── test_tool_registry.py       # 23 registry tests
└── .gitignore                      # Excludes results/, audit/, *.chain, *.pending, *.json, *.pcap ...
```

---

## 12. Glossary

| Term | Definition |
|---|---|
| CRTP | Collaborative Resonance Transfer Protocol — multi-agent communication standard (Roadmap) |
| Guardian_Codex | Immutable policy-as-code repository |
| IRP | Interoperable Resilience Protocol — governance framework for human-AI collaboration |
| KKI | Kali Kimi Interface — sovereign tooling layer for OS capability mediation |
| Mirror_RTC | Real-time consent gate requiring operator cryptographic attestation |
| Mnemosyne | Append-only, tamper-evident audit memory system |
| MOD-045 | Behavioral compliance stack requiring per-action authorization and tamper-evident audit |
| Snap-Back | Reversible workspace state capture before dangerous execution |
| TOCTOU | Time-of-check to time-of-use — race between verification and execution |

---

## 13. Changelog

### v2.1 — DH-KKI-IRP-003 (current)

- **Closed:** orchestrator bypass — all tools route through `GovernedExecutor`.
- **Closed:** masscan/tshark L2 hardening — `KaliToolAdapter.masscan_scan` (rate ceiling)
  and `tshark_capture` (interface allowlist + duration bound); registered harness tools.
- **Closed:** snap-back recovery for workspace mutations (scoped, repo-root/`.git` guarded).
- **Closed:** audit chain read-back tamper detection (`AuditLog.verify_file`) with
  entry-level precision.
- **Closed:** consent→exec TOCTOU — single attestation per `_gate()`, hash bound into the
  consent prompt.
- **Removed:** `--ungoverned` CLI flag (`governed` parameter retained for test injection).
- **Tests:** 103 passed, 3 skipped, 0 failed.

### v2.0 — DH-KKI-IRP-002

- **Added:** core governance layer (validation, attestation, policy, consent, audit, engine).
- **Added:** governance unit tests + `docs/IRP_GOVERNANCE.md` spec-to-status mapping.

### v1.0 — Base KKI

- **Added:** L0–L4 stack with `DANGEROUS_CHARS` blacklist, argument arrays, timeout,
  truncation, and L2 adapter tests.

---

## 14. Contact & Attribution

- **Architecture:** Joseph (Starwreck) Byram, Hue & Logic Labs
- **Philosophy:** First-principles governance from 2,900°F catastrophic-risk management
- **License:** MIT (governance layer) + upstream tool licenses (L0 binaries)
- **Repository:** `kali-kimi-interface`
- **PR:** #1 (DH-KKI-IRP-002 / DH-KKI-IRP-003)

> "The same methodology I use staging 100-pound slag balls along a 50-yard pour route —
> cooler ball pulls more slag, cleaner pours, fewer failures — is how I approach AI safety:
> understand every layer, control every variable, build the failsafe yourself."

---

*Document Version: 2.1.0 — Last Updated: 2026-06-10 — Classification: Open Source, Defensive
Security Architecture*
