# Governed Autonomy for Offensive Tooling
## A stdlib-only consent, attestation, and audit layer between AI agents and Kali Linux

**Whitepaper — Version 1.0**
**Author:** Joseph (Starwreck) Byram — Hue & Logic Labs
**Project:** Kali Kimi Interface (KKI) — IRP Governance Stack
**Date:** 2026-06-10
**Classification:** Open Source · Defensive Security Architecture

---

## Abstract

Large language models can now select and operate real penetration-testing tools. That
capability collapses the distance between a model's reasoning and a host's raw power: a
single generated JSON object can become `nmap`, `sqlmap`, or `masscan` running against a
live network. The Kali Kimi Interface (KKI) addresses the resulting governance gap with an
**additive, standard-library-only** control plane that sits between the agent and the
operating system. It enforces one non-negotiable invariant: **no `danger-full-access` tool
reaches `subprocess.run` without passing positive-allowlist validation, per-invocation
binary attestation, an explicit operator consent (`APPROVE` + nonce), and an append-only,
tamper-evident audit entry.** This paper describes the architecture, the threat model it
defends, the implementation of each control, and the verification — 106 automated tests and
a five-check acceptance suite executed on live Kali hardware — that demonstrates the
invariant holds, fails closed, and does not regress existing protections.

---

## 1. Introduction

KKI began as a text interface and Python toolkit wrapping ~152 Kali tools for use by AI
agents and security professionals. The toolkit already provided a safe execution layer
(input validation, structured JSON output, timeouts) and a verifiable registry with SHA-256
binary hashes. What it lacked was a *governance* layer: a place where policy, human
authority, and non-repudiable memory gate execution — independent of whatever the model
decided to do.

The design goal was deliberately conservative:

- **Additive, not replacing.** Every existing protection (the `DANGEROUS_CHARS` blacklist,
  argument-array execution, rate limits, timeouts) remains in place. The governance stack is
  layered *on top*.
- **Standard library only.** No third-party cryptography, no daemons, no kernel features are
  required to run the core. Heavier options (asymmetric signing, namespace sandboxing) are
  documented as upgrade paths, not dependencies.
- **Fail-closed by default.** Absence of a decision is a denial. A missing binary, a denied
  consent, a validation error, or a silent timeout all abort execution at the earliest layer.

## 2. Threat Model

KKI assumes the reasoning model is *capable but untrusted* and that tool inputs may be
adversarial. The controls target the following threats:

| Threat | Vector | Control |
|---|---|---|
| Command injection | Metacharacters in a target/flag echoed into a command line | Positive allowlist (IPv4/IPv6/CIDR, RFC 1123 host) + `DANGEROUS_CHARS` blacklist + argument-array execution (`shell=False`) |
| Prompt-driven over-reach | Model "reasons" itself into a destructive scan/exploit | Permission-as-code; `danger-full-access ⇒ REQUIRES_CONSENT`; per-action operator `APPROVE` |
| Binary substitution | PATH hijack, symlink redirection, swapped binary | Per-invocation `realpath` + trusted-directory containment + fresh SHA-256 |
| Time-of-check/time-of-use | Binary verified, then a different one runs | Single attestation per gate; attested hash bound into the consent prompt; same attestation used for execution |
| Resource exhaustion | Runaway scan rate, infinite loop, output flooding | Rate ceilings (e.g. masscan ≤ 100 000 pps), timeouts, output truncation, round/depth budgets |
| Evidence tampering | Editing or deleting the activity log after the fact | Append-only, hash-chained, HMAC-tagged audit trail with read-back verification |
| Homoglyph / encoding evasion | Unicode look-alikes, null bytes | NFKC normalization, null-byte rejection, length bounds |

Out of scope for the stdlib tier (documented as upgrade paths): kernel-level sandboxing,
cross-host non-repudiation with asymmetric keys, and grammar-constrained model output.

## 3. Architecture

KKI is organized as a layered stack. The original toolkit provides L0–L4; the governance
stack wraps the executor with stronger gates.

```
L4  Orchestration loop (orchestrator.py)      prompt → model → JSON → execute → repeat
L3  Harness registry (harness_integration.py) ToolSpec: schema + permission + handler
L2  Safe execution (src/kali_tools.py)        validate → rate-limit → timeout → parse
L1  Identity & verification (attestation.py)  realpath + SHA-256 + trusted-directory
L0  OS binaries (Kali tools)                  nmap, sqlmap, masscan, tshark, gobuster, …

        Governance layer (src/governance/)
        ─────────────────────────────────
        engine.py        GovernedExecutor: wires the pipeline + preview
        policy.py        permission-as-code; blast-radius classification
        consent.py       Mirror_RTC: per-action APPROVE + nonce, default-deny
        audit.py         Mnemosyne: append-only HMAC hash chain
        validation.py    positive allowlist; NFKC; homoglyph/null-byte rejection
        attestation.py   per-invocation binary identity verification
```

The governance layer comprises **seven modules** (six functional + package init) totaling a
few thousand lines of dependency-free Python.

## 4. The Core Invariant

> A `danger-full-access` tool never executes without a fresh operator `APPROVE <nonce>`.

Operationally, `GovernedExecutor._gate()` runs every proposed call through this pipeline:

1. **Validate** — content validation (`validation.py`) inside policy evaluation. Bad input
   is rejected *before* any permission decision.
2. **Evaluate** — `policy.evaluate(tool, permission, params)` returns a `PolicyDecision`
   carrying a `BlastRadius` (`RECON` / `WRITE` / `DANGER`) and an `Authorization`
   (`GRANTED` / `DENIED` / `REQUIRES_CONSENT`). `danger-full-access` maps to
   `REQUIRES_CONSENT`.
3. **Attest** — `attest_binary()` resolves the binary via `realpath`, confirms containment
   in a trusted directory, and computes a fresh SHA-256. Computed **once** per gate.
4. **Consent** — for `REQUIRES_CONSENT`, the `ConsentGate` issues a challenge that includes
   the attested hash and a cryptographic nonce. Only an exact `APPROVE <nonce>` authorizes;
   timeout, wrong nonce, or no operator all resolve to **DENY**.
5. **Execute** — only on approval, via the underlying executor as an argument array.
6. **Audit** — every decision, denial, and execution is appended to the hash chain.

Because attestation is computed once and the same attestation flows from the consent prompt
into execution, the operator approves *the specific binary hash the gate computed* — closing
the **consent→execution swap** window (execution never re-attests to a different result). One
residual race remains and is stated honestly: between hashing the binary and spawning the
process, a file replaced on disk would execute unverified. That attest→exec disk race is only
fully closed by fd-pinned execution (`fexecve`) or namespacing — see §8. The hash baseline is
also trust-on-first-use: it is captured when the verifiable registry is built at startup, so
attestation detects post-startup replacement but treats a pre-existing compromised binary as
its own baseline unless a reviewed manifest is pinned.

## 5. Implementation

**Validation (`validation.py`).** Reject-by-default. Targets must match an IPv4/IPv6/CIDR
pattern (via the `ipaddress` module) or an RFC 1123 hostname; URLs are scheme-checked. All
inputs pass through NFKC normalization (defeating homoglyph look-alikes), null-byte
rejection, and length bounds. Flags are constrained by a per-tool `SAFE_FLAGS` allowlist,
closing the documented free-text `{flags}` interpolation sharp edge.

**Attestation (`attestation.py`).** `TRUSTED_DIRS` is `/usr/bin`, `/usr/sbin`,
`/usr/local/bin`, `/usr/local/sbin`, `/bin`, `/sbin`. Containment is checked with
`os.path.commonpath` on resolved paths — not string prefixes — so a directory like
`/usr/bin-evil` cannot masquerade as trusted. The `Attestation` record reports
`installed`, `in_trusted_dir`, `sha256`, `hash_matches` (when an expected hash is supplied),
and a single `verified` boolean.

**Policy (`policy.py`).** Permission-as-code. The permission classification originates on the
harness `ToolSpec` and is mapped to a blast radius. Network scanners and exploit tools are
`danger-full-access`; reconnaissance is `read-only`; file/report writers are
`workspace-write`. An optional network-scope allowlist gates targets by CIDR.

**Consent (`consent.py`).** The Mirror_RTC gate is default-deny with a 30-second timeout.
The prompt function has the contract `Callable[[ConsentRequest], Optional[str]]`; a `None`
return (no response) is a denial. Nonces are compared in constant time. Unresolved and
denied actions are retained for a boundary report at session close.

**Audit (`audit.py`).** The Mnemosyne trail is append-only. Each entry carries a sequence
number, timestamp, category, payload, the previous entry's hash, this entry's hash, and an
HMAC tag. `verify()` checks the chain in memory; `verify_file(path, key=None)` reads a
persisted chain back and re-walks the **keyless** SHA-256 linkage, catching payload tampering
and chain breaks at the exact entry. Supplying the original key additionally verifies the
HMAC.

**Engine (`engine.py`).** `GovernedExecutor` wires the pipeline and offers `preview()` — a
read-only pre-flight (`ExecutionPreCheck`) that reports the permission level, scope status,
normalized target, accepted/rejected flags, and estimated blast radius without executing.

**Orchestrator wiring (`orchestrator.py`).** Governance is always on from the CLI; there is
no `--ungoverned` flag. masscan and tshark — formerly direct-`subprocess` wrappers that
bypassed L2 — are now first-class adapter methods with a rate ceiling and an interface
allowlist, routed through the same gate as every other tool. Danger/workspace-write tools
take a snap-back snapshot of `<work_dir>/workspace` (guarded against ever copying the repo
root or a `.git` checkout) and roll back on failure or denial.

## 6. Verification & Results

**Automated suite.** The repository ships 111 test functions across five files —
`test_governance.py` (43), `test_kali_tools.py` (29), `test_tool_registry.py` (23),
`test_orchestrator_governance.py` (11), and `test_kali_integration.py` (5). In a bare
container the result is **106 passed, 5 skipped, 0 failed**; the five skips are localhost and
live-binary integration checks that only run where the tools are installed.

**Live-hardware acceptance.** The five-check acceptance suite was executed on real Kali
hardware (Kali 6.18.3, Python 3.13.11), and all five pass — including the privileged syn-scan
path under `sudo`:

1. **Attestation is real.** `attest_binary("nmap")` produced a 64-character SHA-256 equal to
   `sha256sum /usr/bin/nmap`, with `verified=true` and `in_trusted_dir=true`.
2. **Rate ceiling enforced pre-subprocess.** A masscan request above 100 000 pps is rejected
   before any process spawns.
3. **Interface allowlist enforced.** A tshark capture on a non-allowlisted interface
   (`docker0`) is rejected.
4. **Fail-closed under no-consent.** With no operator response, the gate returned
   `allowed=false`, reason "consent timeout: operator did not authorize", and the target
   tool **never executed**.
5. **Approve path + audit integrity.** With a valid `APPROVE <nonce>`, the governed nmap ran;
   the audit chain verified clean; and a single-byte flip in the persisted chain was caught
   at the exact entry.

Notably, the first live run surfaced the fail-closed behavior *before* a test stub was
corrected: the gate denied on consent timeout exactly as designed. That was the invariant
working — not a defect — and it is the strongest possible evidence that the default is deny.

## 7. Security Guarantees

| Guarantee | Enforcement | Not bypassable by |
|---|---|---|
| No command injection | positive allowlist + `DANGEROUS_CHARS` + argument arrays | prompt injection, target echo |
| No shell interpretation | argument arrays (`shell=False`) on the governed execution path (L2 adapter + `GovernedExecutor`) | metacharacters in any parameter reaching the agent path |
| Bounded resources | rate limit + timeout + truncation + round/depth caps | runaway loops, context flooding |
| Tool integrity | per-invocation SHA-256 + realpath containment | PATH hijack, symlink, binary swap |
| Operator sovereignty | consent nonce + default-deny | automated override, timed bypass |
| Non-repudiable audit | SHA-256 hash chain (+ optional HMAC) | log deletion, entry edit, reorder |

## 8. Known Limitations & Upgrade Paths

Honesty about what the stdlib tier does *not* solve is a design principle, not an afterthought:

- **HMAC signing is session-local.** The HMAC key is ephemeral and not persisted, so
  cross-session/process non-repudiation requires key management the standard library does not
  provide cleanly. The keyless hash chain still detects tampering within and across runs.
  *Upgrade:* Ed25519 asymmetric signing + HSM.
- **No Linux namespace sandboxing.** `subprocess.run(..., shell=False)` plus argument arrays
  is the current execution boundary. *Upgrade:* `unshare` / `setcap` / seccomp.
- **No grammar-constrained model output.** Defensive JSON extraction and schema validation
  guard the boundary. *Upgrade:* native forced tool-use APIs.
- **Multi-agent coordination is roadmap.** The `preview()` / `execute()` separation exists;
  distributed agent negotiation is not implemented.
- **Attestation is hard-enforced for `danger-full-access` and `workspace-write`.** A tool
  that mutates state must run a verified binary; an attestation failure (untrusted path or
  hash mismatch) blocks execution. `read-only` tools remain advisory — their attestation is
  logged but not blocking — a deliberate scope choice, since they do not mutate state.
- **The interactive menu runs at operator privilege.** `kali_start_menu.py` is a human-only
  front-end; it parses operator input with `shlex` and runs argument arrays (`shell=False`),
  so it does not interpret shell metacharacters, but it still executes at the operator's own
  privilege and is not gated by `GovernedExecutor`. Every guarantee in this paper applies to
  the `GovernedExecutor` path.

## 9. Methodology

The architecture reflects a first-principles, build-your-own-failsafe discipline: understand
every layer, control every variable, and make the safe path the default path. The same logic
that governs a high-consequence physical process — stage the inputs, verify each one, fail
toward safety — is applied to autonomous tooling. The result is not a smarter model; it is a
boundary the model cannot cross without a human in the loop and a record that cannot be
quietly erased.

## 10. Conclusion

KKI demonstrates that meaningful governance of AI-operated offensive tooling does not require
exotic dependencies. A few thousand lines of standard-library Python — validation,
attestation, policy, consent, and a tamper-evident audit chain — are sufficient to enforce a
hard invariant, fail closed under uncertainty, and produce verifiable evidence. The controls
were proven on live Kali hardware, and the limitations are stated plainly with concrete
upgrade paths. For authorized security testing and education, this is a deployable, auditable
foundation for keeping the operator sovereign over the machine.

---

*References: see `docs/IRP_GOVERNANCE.md` (architecture, API, compliance matrix) and
`tests/test_kali_integration.py` (acceptance checks). Repository: `kali-kimi-interface`.*

*"Understand every layer, control every variable, build the failsafe yourself."*
