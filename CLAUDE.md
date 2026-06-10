# CLAUDE.md

Guidance for AI assistants (Claude Code and others) working in this repository.

## What this project is

**Kali Kimi Interface (KKI)** is a text-based interface and Python toolkit that wraps
Kali Linux penetration-testing tools for use by AI agents and security professionals.
It provides three things:

1. An **interactive terminal menu** for discovering and launching ~159 security tools.
2. A **safe execution layer** (input validation, structured JSON output) so tools can be
   driven programmatically by an LLM harness.
3. A **verifiable tool registry** with SHA-256 binary integrity hashes, JSON Schemas, and
   permission classifications for each tool.

There is also an **orchestrator** that delegates assessment tasks to an external "Kimi"
reasoning CLI, which selects tools and analyzes results in a loop.

> **Scope/ethics:** This is tooling for *authorized* security testing and education. When
> changing execution behavior, preserve the safety guarantees (validation, permission
> gating, timeouts). Do not weaken injection protections or remove permission checks.

## Repository layout

```
kali-kimi-interface/
├── kali_start_menu.py        # Interactive TUI menu (entry point, ~26KB)
├── kali_tools_list.py        # Non-interactive tool catalog / search (CLI)
├── orchestrator.py           # Kimi-driven assessment loop (CLI, depends on src/)
├── src/
│   ├── kali_tools.py         # KaliToolAdapter: safe wrappers + output parsers
│   ├── harness_integration.py# SecurityToolExecutor: ToolSpec registry for a harness
│   ├── tool_registry.py      # VerifiableToolRegistry: 152 tools, SHA-256, schemas
│   ├── network_mapper.py     # NetworkMapper: WiFi + Ethernet discovery
│   └── governance/           # IRP governance layer (allowlist, policy, consent, audit)
│       ├── validation.py     #   positive allowlist validation + SAFE_FLAGS
│       ├── attestation.py    #   per-invocation binary attestation (PATH/symlink defense)
│       ├── policy.py         #   PolicyEngine: permission-as-code; DANGER ⇒ consent
│       ├── consent.py        #   ConsentGate (Mirror_RTC): per-action APPROVE <nonce>
│       ├── audit.py          #   AuditLog: append-only HMAC hash-chained trail
│       └── engine.py         #   GovernedExecutor: wires the pipeline + preview CLI
├── tests/
│   ├── test_kali_tools.py    # Adapter tests (validation, parsing, rate limit)
│   ├── test_tool_registry.py # Registry tests (hashing, verification)
│   └── test_governance.py    # Governance tests (allowlist, attestation, consent, audit)
├── docs/
│   ├── KALI_START_MENU_GUIDE.md
│   ├── METHODOLOGY_CASE_STUDY.md  # How-to on the layered DIY-on-OS methodology
│   └── IRP_GOVERNANCE.md          # Governance layer spec-to-status + integration guide
├── topology/
│   └── cove-lan-topology.html# Standalone interactive network map visualization
├── requirements.txt          # Stdlib-only core; optional deps commented out
└── README.md
```

## Module responsibilities & how they fit together

- **`src/kali_tools.py` — `KaliToolAdapter`**: the core safe-execution engine. Wraps
  specific tools (`nmap_scan`, `sqlmap_scan`, `gobuster_scan`, `nikto_scan`,
  `quick_recon`). Validates targets (`_validate_target`), enforces rate limiting
  (`_check_rate_limit`), runs subprocesses with timeouts (`_execute_tool`), and parses
  output into structured dicts (`_parse_nmap_output`, `_parse_sqlmap_output`, etc.).
  Returns `SecurityToolResult` dataclasses with `.to_dict()` / `.to_json()`.
- **`src/harness_integration.py` — `SecurityToolExecutor`**: registers tools as
  `ToolSpec`s (name, description, JSON `input_schema`, `required_permission`, handler)
  and dispatches `execute(tool_name, params)` to `KaliToolAdapter`. This is the bridge an
  LLM tool-calling harness uses.
- **`src/tool_registry.py` — `VerifiableToolRegistry`**: the catalog of record. Builds
  `ToolVerif` records from `TOOL_DEFINITIONS` (a list of tuples), computes SHA-256 of each
  installed binary, exposes `verify_tool`, `verify_all`, `integrity_report`,
  `validate_input`, and `save_manifest`. Run as a CLI to verify integrity or emit a
  manifest.
- **`orchestrator.py` — `KaliKimiOrchestrator`**: top-level loop. Sends task + available
  tools to the external Kimi CLI, parses Kimi's JSON tool calls, executes them, feeds
  results back. Adds `src/` to `sys.path` at runtime. **Always governed from the CLI:**
  every tool call is routed through `GovernedExecutor` (`_governed_dispatch`), so policy +
  attestation + consent + audit gate execution. masscan/tshark are now first-class harness
  tools (no direct-subprocess wrappers). For danger/workspace-write tools the orchestrator
  takes a scoped snap-back of `<work_dir>/workspace` (never the repo root) and rolls back on
  failure. Each session writes a Mnemosyne mirror under `<work_dir>/audit/`. There is **no
  `--ungoverned` CLI flag**; the `governed` constructor parameter exists for test injection
  only. `--network-scope CIDR` enforces the scope gate.
- **`src/network_mapper.py` — `NetworkMapper`**: discovers devices via WiFi/Ethernet,
  resolves OUI manufacturers, and produces/saves JSON network maps.
- **`src/governance/` — IRP governance layer**: an *additive*, stdlib-only stack that wraps
  the executor with stronger gates. `GovernedExecutor` (engine.py) runs every proposed tool
  call through positive allowlist validation (validation.py) → permission-as-code policy
  (policy.py, `DANGER ⇒ REQUIRES_CONSENT`) → per-invocation binary attestation
  (attestation.py) → the Mirror_RTC human consent gate (consent.py, default-deny) → the
  underlying `SecurityToolExecutor`, recording each step in an append-only HMAC hash-chained
  audit log (audit.py). **Core invariant:** a `danger-full-access` tool never executes
  without an operator `APPROVE <nonce>`. It does **not** remove any existing control — the
  `DANGEROUS_CHARS` blacklist stays as defense-in-depth. See `docs/IRP_GOVERNANCE.md`.
- **`kali_start_menu.py` / `kali_tools_list.py`**: human-facing front ends. The menu
  builds its own tool database (`_build_tool_database`) and detects installed tools.

**Important nuance:** the tool catalog exists in more than one place. `tool_registry.py`'s
`TOOL_DEFINITIONS` (159 tuple entries, deduped to **152** unique tools across 14
categories), `kali_start_menu.py`'s `_build_tool_database`, and `kali_tools_list.py` each
maintain their own listing. The adapter (`kali_tools.py`) only implements safe wrappers
for a handful (nmap, sqlmap, gobuster, dirb, nikto, hydra, etc.). If you add or rename a
tool, update every listing that should know about it, and keep README counts consistent.

## Running things

```bash
# Interactive menu
python3 kali_start_menu.py

# Catalog / search (non-interactive)
python3 kali_tools_list.py --compact
python3 kali_tools_list.py --list
python3 kali_tools_list.py --category "Web Applications"
python3 kali_tools_list.py --search sql

# Direct tool execution via adapter
python3 src/kali_tools.py nmap 192.168.1.1 --type syn --ports 1-1000

# Verifiable registry
python3 src/tool_registry.py --verify nmap
python3 src/tool_registry.py --verify-all
# (also supports emitting a manifest — see the argparse block at the bottom of the file)

# Network mapping
python3 -m src.network_mapper --ethernet --scan-ports
python3 -m src.network_mapper --wifi wlan0

# Orchestrator (requires the external Kimi CLI + target)
# Kimi is auto-located via PATH / the KIMI_CLI env var / ~/.local/bin/kimi;
# override with --kimi-cli, and the work dir defaults to the repo root.
python3 orchestrator.py --target 192.168.1.0/24 --task "full recon" --depth standard
python3 orchestrator.py --target example.com --task "web scan" --kimi-cli /path/to/kimi
```

## Tests

```bash
pip3 install pytest        # not bundled; install first
python3 -m pytest tests/ -v
```

- Tests are **pytest-style** (test classes with `test_*` methods, plain `assert`).
- `tests/test_kali_tools.py` covers input validation, command-injection blocking, output
  parsing (nmap XML/text, gobuster, nikto, sqlmap), rate limiting, and a couple of
  localhost integration scans.
- `tests/test_tool_registry.py` covers registry construction, binary hashing, and
  verification.
- Integration tests that actually invoke binaries (e.g. `nmap` on localhost) only pass on
  a host where those tools are installed; they may skip/fail in a bare container. Don't
  treat such environment-dependent failures as regressions without checking.
- **No CI workflow exists** in the repo yet. There is no linter or formatter configured.

## Conventions

- **Python 3.6+, standard library only** for core functionality. `requirements.txt` keeps
  optional deps (pytest, colorama, requests) commented out — do not add hard third-party
  dependencies without a strong reason.
- Every module starts with `from __future__ import annotations` and a docstring with a
  usage example. Match that style in new modules.
- **Dataclasses** for structured records (`SecurityToolResult`, `ToolSpec`, `ToolVerif`,
  `NetworkDevice`, `WiFiNetwork`), each typically with `to_dict()` / `to_json()` helpers.
- **Type hints** throughout (`typing.Optional`, `Dict`, `List`, `Tuple`, etc.).
- **JSON-everywhere output**: results are serialized to JSON so an LLM can consume them.
  Preserve this when adding tools or parsers.
- Permission levels are a fixed vocabulary — `read-only`, `workspace-write`,
  `danger-full-access` — mirrored as the `Permission` enum in `tool_registry.py` and
  string constants in `harness_integration.py`. Classify new tools accordingly; network
  scanners and exploit tools are `danger-full-access`.
- CLI entry points use `argparse` inside a `main()` guarded by `if __name__ == '__main__'`.
- Files use emoji icons for categories (🔍 🔎 🌐 🔐 📡 💥 …); keep them consistent with
  existing category labels.

## Security guarantees — do not regress

- **Target validation** (`KaliToolAdapter._validate_target`) rejects empty/non-string
  input and any of the `DANGEROUS_CHARS` (``; & | ` $ ( ) < > \ \n { }``) to prevent
  command injection. Commands are executed as **argument arrays** via `subprocess.run`
  (never `shell=True`).
- **Rate limiting** (`_check_rate_limit`) and **timeouts** (`_execute_tool`) guard against
  abuse and runaway processes. Output is truncated to `max_output_size`.
- `tool_registry.validate_input` validates params against each tool's JSON Schema.
- Note a sharp edge: some `command_template`s in `TOOL_DEFINITIONS` interpolate `{flags}`
  or other free-text fields. Validation is strongest on `target`; treat any field that
  reaches a command line as untrusted and validate it before use.
- `.gitignore` deliberately excludes scan artifacts and secrets (`*.json` except
  `requirements.txt`, `*.pcap`, `*.key`, `*.pem`, `shadow`, `passwd`, `*.log`, etc.).
  **Never commit scan output, captures, wordlists, or credentials.**

## Environment-specific notes

- `orchestrator.py` depends on an **external Kimi reasoning CLI**. It is located at
  runtime by `resolve_kimi_cli()` in this order: the `--kimi-cli` flag → the `KIMI_CLI`
  environment variable → `kimi` on `PATH` → `~/.local/bin/kimi`. The working directory
  defaults to the repo root (`--work-dir` to override), and session results are written to
  `<work_dir>/results/`. If no Kimi binary is found the orchestrator fails fast with a
  clear message and exit code 1 — it does **not** assume any operator-specific path. The
  Kimi CLI still won't be present in a bare container, so the orchestrator can't actually
  run an assessment here.
- Many tools and wordlists (`/usr/share/wordlists/...`) only exist on a real Kali install.
  Logic should degrade gracefully (the registry already detects installed vs. missing).

## Git workflow

- Work on descriptive feature branches (e.g. `feature/<name>`, or `claude/<topic>` for
  agent-authored changes); don't commit directly to `main`.
- Commit messages follow a `type: summary` style (e.g. `feat: ...`), often with a short
  scope/impact note. Keep them descriptive.
- After pushing, open a **draft PR** if none exists.
- Don't push to `main` without explicit permission.
