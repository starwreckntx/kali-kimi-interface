# KKI IRP Governance Stack — Phased Implementation Roadmap

**Owner:** Joseph (Starwreck) Byram — Hue & Logic Labs
**Scope:** Kali Kimi Interface (KKI) governed-autonomy stack
**Status snapshot:** Phases 0–3 complete · Phase 4 landed · 115 passed / 5 skipped / 1 xfailed
· validated on Kali 6.18.3 · adversarial benchmark **8/8 active vectors defeated, 1 residual**

This roadmap absorbs both numbering schemes used so far — the `DH-KKI-IRP-00X` delivery tags
and the version-tier upgrade paths (`2.2`–`3.0`) in `docs/IRP_GOVERNANCE.md` §10 — into one
ordered list. Each phase states its **goal, deliverables, acceptance criteria, dependency
tier, and the findings/components it closes.**

**Dependency tiers** (the project's core constraint is stdlib-only):
- **T0 stdlib** — Python standard library only. Phases 0–6 stay here.
- **T1 third-party** — requires a vetted dependency (e.g. `cryptography`, `fido2`).
- **T2 OS/kernel** — requires Linux capabilities/namespaces or a privileged daemon.

---

## ✅ Phase 0 — Base toolkit (DONE, pre-governance)

- **Goal:** Wrap ~152 Kali tools behind a safe, programmable execution layer.
- **Deliverables:** `tool_registry.py` (159 defs → **152 unique** tools, 14 categories,
  SHA-256 hashing), `kali_tools.py` L2 adapter (validation, rate limit, timeout, truncation,
  structured `SecurityToolResult`), `harness_integration.py` ToolSpec registry,
  `kali_start_menu.py`, `kali_tools_list.py`, `network_mapper.py`, `orchestrator.py`.
- **Acceptance:** adapter blocks injection; registry hashes installed binaries.
- **Evidence:** `main@fde875f` and earlier · `test_kali_tools.py` (29), `test_tool_registry.py` (23).
- **Tier:** T0.

## ✅ Phase 1 — Core governance layer (DONE · DH-KKI-IRP-002)

- **Goal:** Insert an additive control plane between the agent and the OS.
- **Deliverables:** `src/governance/` — `validation.py` (positive allowlist, NFKC,
  homoglyph/null-byte), `attestation.py` (realpath + trusted-dir + SHA-256), `policy.py`
  (permission-as-code, blast radius), `consent.py` (Mirror_RTC, default-deny + nonce),
  `audit.py` (append-only HMAC hash chain), `engine.py` (`GovernedExecutor`, `preview`).
- **Acceptance:** danger ⇒ requires consent; default-deny; injection denied before execution.
- **Evidence:** `4b2ecd8` · `test_governance.py` (44).
- **Closes:** IRP Guardian_Codex, Mirror_RTC, Mnemosyne (initial).
- **Tier:** T0.

## ✅ Phase 2 — Orchestrator wiring + L2 hardening (DONE · DH-KKI-IRP-003)

- **Goal:** Make governance unavoidable; remove every bypass.
- **Deliverables:** route all tool calls through `GovernedExecutor`; **remove `--ungoverned`
  CLI flag**; masscan/tshark promoted to first-class L2 adapter methods (rate ceiling +
  interface allowlist), direct-`subprocess` wrappers deleted; snap-back recovery (scoped,
  repo-root/`.git`-guarded); `AuditLog.verify_file` read-back; consent→exec TOCTOU binding
  (single attestation, hash in the prompt); `--network-scope` gate.
- **Acceptance:** no path executes a danger tool without consent; consent denial → zero base
  executor calls.
- **Evidence:** `e8b893d`, `de28787` · `test_orchestrator_governance.py` (11).
- **Tier:** T0.

## ✅ Phase 3 — Documentation, live verification, self-audit (DONE)

- **Goal:** Prove it on real hardware and document it honestly.
- **Deliverables:** `IRP_GOVERNANCE.md` v2.1 (13 draft→reality corrections, runnable
  snippets); `WHITEPAPER.md`; `docs/social/`; `test_kali_integration.py` (5 acceptance
  checks); **live-Kali validation (6.18.3): 5/5 pass**; adversarial self-audit (F1–F8) with
  fixes **F2** (attestation enforced for workspace-write) and **F3** (menu shell-injection
  removed); doc overclaims scoped (F1).
- **Acceptance:** 107 passed / 5 skipped; every doc code snippet runs; live attestation ==
  `sha256sum /usr/bin/nmap`.
- **Evidence:** `564b6a8`, `23690e6`, `90764e9`, `fd9bf06`, `1a7e9ad`, `d58b89f`,
  `b577abc`, `4f9f869`.
- **Closes:** F1, F2, F3.
- **Tier:** T0.

---

## ✅ Phase 4 — Adversarial governance benchmark (LANDED · the "Resultant Seed")

- **Status:** delivered. `tests/test_adversarial_benchmark.py` runs as pytest **and** a
  standalone `--report` / `--json` scorecard: **8/8 active vectors defeated · 1 documented
  residual (V9)**. CI (`.github/workflows/ci.yml`, py3.9/3.11/3.13) runs it on every PR.
  V9 (mid-session swap) is a strict-xfail that flips CI red when Phase 5 closes it.
- **Goal:** Turn governance from *descriptive* to *measurable* — a scored red-team suite.
- **Deliverables:** `tests/test_adversarial_benchmark.py` consolidating existing red-team
  coverage and adding the real gaps, with a `--report` that emits a robustness score.
  Attack vectors:
  | Vector | Today | Phase 4 |
  |---|---|---|
  | Prompt injection | ✅ `test_injection_denied_before_execution` | keep |
  | Hash mismatch | ✅ `test_hash_mismatch_rejected` | keep |
  | Wrong nonce | ✅ `test_wrong_nonce_denied` | keep |
  | Path hijack | ✅ `test_untrusted_path_rejected` | keep |
  | Log tampering | ✅ `test_verify_file_detects_single_entry_tamper` | keep |
  | **Nonce replay** (reuse an old approval) | ❌ | **add** |
  | **Mid-session binary swap** (attest→exec race) | ⚠️ partial | **add** |
  | **Delegated/second-agent bypass** | ❌ | **add** |
  | **Approval spoofing** (forge consent dict) | ⚠️ partial | **add** |
- **Acceptance:** every vector has a deterministic test; `--report` prints a pass/fail score
  that can be cited in the whitepaper; the mid-session-swap and delegated-agent tests fail
  *today* (proving they bite) and pass after Phase 5.
- **Also:** add **CI** (GitHub Actions running `pytest tests/`) — there is no CI workflow yet.
- **Closes:** measurability for F5; sets up Phase 5.
- **Tier:** T0.

## ⏭ Phase 5 — Attestation hardening (audit F4 + F5)

- **Goal:** Execute *the exact bytes that were attested*, against a *reviewed* baseline.
- **Deliverables:**
  - **F5 — bind exec to attestation:** run the attested `real_path` (not an independently
    re-resolved path); where feasible, hold an open fd from attestation time and use
    `os.execve`/`fexecve`-style execution to shrink the disk-race window.
  - **F4 — pinned manifest:** `--manifest <file>` loads reviewed known-good hashes (via
    `VerifiableToolRegistry.save_manifest`/load) so attestation compares against a pinned
    baseline instead of trust-on-first-use.
- **Acceptance:** Phase 4's mid-session-swap and path-divergence tests pass; a tampered
  binary fails even when it sits in a trusted dir.
- **Closes:** F4, F5.
- **Tier:** T0 (fd-pinned exec) — full closure of the disk race overlaps Phase 8 (T2).

## ⏭ Phase 6 — Tool-surface expansion + PurpBox reconciliation

- **Goal:** Merge the PurpBox "Phase 1 proof-of-life" work into the governed branch without
  losing it or weakening any gate.
- **Deliverables:** back up PurpBox working tree (✅ tarball done); secrets-safe push of the
  uncommitted code to `purpbox/phase1-wip`; reconcile the ~15 new tool registrations
  (`dnsrecon_scan`, `wpscan_scan`, `searchsploit_query`, `radare2_scan`, `binwalk_scan`,
  `apktool_decompile`, `steghide_info`, `netcat_port_scan`, …) on top of the governance
  versions of `harness_integration.py`/`kali_tools.py`; evaluate `parallel_orchestrator.py`,
  `permission_gate.py`, `tool_classification.py` for integration vs. supersession.
- **Acceptance:** each new tool has correct permission class + JSON schema + `SAFE_FLAGS`,
  routes through the gate, and passes attestation; registry/menu/list counts stay consistent;
  parallel execution (if adopted) preserves per-action consent.
- **Risk:** parallel orchestration must not batch-approve — each danger action keeps its own
  consent. Treat `permission_gate.py` as either superseded by `policy.py` or a complementary
  layer, decided by diff review.
- **Tier:** T0.

---

## 🔭 Phase 7 — Cryptographic non-repudiation (roadmap 2.2 / 2.3)

- **Goal:** Cross-session/process audit integrity and stronger consent transport.
- **Deliverables:** Ed25519 asymmetric audit signing (sign `entry_hash`; `verify_file`
  checks signatures with a public key) replacing/augmenting session-local HMAC; key
  management; optional FIDO2/YubiKey consent transport (`prompt_fn` plugin).
- **Acceptance:** a saved chain verifies on a *different* host with only the public key;
  hardware-token approval path works end-to-end.
- **Closes:** F6 (HMAC-ephemeral limitation).
- **Tier:** **T1** (`cryptography`/`pynacl`, `fido2`) — opt-in beyond the stdlib core.

## 🔭 Phase 8 — OS-level sandboxing (roadmap 2.4 / 2.5)

- **Goal:** Constrain what an executed tool can do, and fully close the attest→exec race.
- **Deliverables:** capability dropping (`unshare`/`setcap`/seccomp) so tools run with least
  privilege; network-namespace isolation (`ip netns` + veth) to bound blast radius;
  `fexecve` against the attestation-time fd to eliminate the disk race.
- **Acceptance:** a tool cannot touch resources outside its namespace; a binary swapped
  between hash and spawn cannot be executed.
- **Closes:** residual TOCTOU; "No Linux namespace sandboxing" limitation.
- **Tier:** **T2** (kernel features; likely a small privileged helper / `kkid` daemon).

## 🔭 Phase 9 — Constrained generation + multi-agent governance (roadmap 2.6 / 3.0 · CRTP)

- **Goal:** Make malformed/over-reaching tool calls impossible to emit, and govern multiple
  agents.
- **Deliverables:** grammar-constrained / forced tool-use output (provider-native) so the
  model can only emit schema-valid calls; distributed multi-node governance with policy
  consensus; CRTP multi-agent coordination where each delegated agent carries its own
  consent + audit lineage.
- **Acceptance:** non-schema tool calls are unrepresentable; the Phase 4 delegated-agent
  benchmark passes under multi-node policy.
- **Closes:** CRTP roadmap item; "no grammar-constrained output" limitation.
- **Tier:** **T1/T2** (provider API + consensus layer).

---

## Sequencing & rationale

```
Phase 0 ─ base toolkit            ✅
Phase 1 ─ core governance         ✅   (additive, stdlib)
Phase 2 ─ wiring + L2 hardening   ✅   (close bypasses)
Phase 3 ─ docs + live verify      ✅   (prove + self-audit; F1/F2/F3)
   │
   ├─ Phase 4 ─ benchmark         ⏭   make robustness measurable (+CI)
   │     └─ surfaces the exact failures Phase 5 must fix
   ├─ Phase 5 ─ attestation T0    ⏭   F4 (pinned manifest) + F5 (exec attested bytes)
   └─ Phase 6 ─ tool expansion    ⏭   reconcile PurpBox Phase-1 work (parallel track)
        │
        ▼  (cross the stdlib boundary — opt-in tiers)
   Phase 7 ─ Ed25519 / FIDO2      🔭   T1  non-repudiation (F6)
   Phase 8 ─ namespaces / fexecve 🔭   T2  sandbox + close disk race
   Phase 9 ─ constrained gen +    🔭   T1/T2  CRTP multi-agent
            multi-agent
```

**Why this order:** Phase 4 before 5 because you fix what you can measure — the benchmark
makes the mid-session-swap and delegated-agent holes concrete (failing tests) so Phase 5's
fixes have a target. Phase 6 runs in parallel (it's about breadth, not the core invariant).
Phases 7–9 are deliberately **after** the stdlib boundary: each buys real assurance but adds
a dependency or kernel surface, so they're opt-in tiers, not core. The core stays deployable
with zero third-party packages through Phase 6.

## Findings → phase map

| Finding | Phase | Status |
|---|---|---|
| F1 TOCTOU/shell doc overstatement | 3 | ✅ fixed |
| F2 attestation danger-only | 3 | ✅ fixed (now danger + workspace-write) |
| F3 menu `shell=True` injection | 3 | ✅ fixed |
| F4 trust-on-first-use baseline | 5 | planned (pinned manifest) |
| F5 attested-path ≠ executed-path | 5 | planned (bind exec to attestation) |
| F6 HMAC session-local | 7 | planned (Ed25519) |
| F7 unused `authorize()` | 6 | prune during reconciliation |
| F8 `network_mapper` outside gate | 6 | review interface-name handling |
| residual attest→exec disk race | 8 | planned (`fexecve`/namespacing) |
