# Hermes Integration

> **Adapter:** `src/hermes_harness.py`
> **Dispatcher:** `hermes_dispatcher.py`
> **Skill:** `kali-harness` / `kali-harness-actions`

## Overview

The Hermes integration turns KKI into a direct execution backend for Hermes. Hermes acts as planner/reconciler only; the harness module executes tools and writes verifiable session artifacts.

Flow:

```
OPERATOR → HERMES → HermesHarness → KaliToolAdapter → Kali tools
              │                │
              │                └── results/<session_id>.json
              │
              └── HermesDispatcher for multi-phase plans
```

## Install

```bash
cd /home/starwreck/kali-kimi-interface
python3 -c "from src.hermes_harness import HermesHarness; print('ok')"
```

No external dependencies required. Uses stdlib only.

## Usage

### Single Tool

```python
from src.hermes_harness import HermesHarness

harness = HermesHarness(governance=True)
result = harness.execute('searchsploit_query', {
    'term': 'apache',
    'timeout': 30,
})
print(result.to_json())
print(result.verifier['claim_check'])
```

Result fields:

- `status`: `success` or `failed`
- `artifacts[0].sha256`: SHA-256 of the session JSON
- `verifier.claim_check`: short status string for RECONCILE
- `authority_log`: ports/paths/network/processes touched
- `parsed_output`: tool-specific structured output

### Discovery

```python
print(len(harness.list_tools()))
print(len(harness.list_tools(installed_only=True)))
print(harness.integrity_report())
harness.verify_all()
```

Registry state: 152 registered, 78 installed.

### Multi-phase Dispatch

```bash
python3 hermes_dispatcher.py --target 192.168.1.1 --task "full recon" --json
python3 hermes_dispatcher.py --target example.com --task "web scan" --depth quick
python3 hermes_dispatcher.py --phases phases.json --telegram-confirm --governance on
```

Presets:

- `full recon` → `quick_recon`
- `web scan` → `whatweb`, then `nikto_scan`

Custom phases via JSON file:

```json
[
  {"tool": "searchsploit_query", "params": {"term": "nginx", "timeout": 30}},
  {"tool": "dnsrecon_scan", "params": {"domain": "example.com", "timeout": 30}}
]
```

## Governance

Default is `governance=True`.

| Toggle | Behavior |
|--------|----------|
| `governance=True` | validates input schema; blocks `danger-full-access` tools; records `unauthorized_attempts` |
| `governance=False` | no preflight gates; for internal testing only |

Danger-tier confirmation:

```bash
python3 hermes_dispatcher.py --phases phases.json --telegram-confirm
```

Before any `danger-full-access` tool runs, Hermes sends a Telegram confirmation prompt and polls for Y/N. Auto-rejects after 5 minutes.

## Hermes Skills

Two skills are installed:

- `kali-harness` — adapter overview, return contract, governance
- `kali-harness-actions` — action reference: `execute`, `list_tools`, `verify_all`

Load in Hermes:

```
load skill kali-harness
load skill kali-harness-actions
```

## Return Contract

`HarnessResult` always contains:

- `packet_type`: `RESULT`
- `status`: `success` | `failed`
- `tool`, `command`, `returncode`, `duration_ms`
- `parsed_output`: structured tool output
- `artifacts`: list with at least one `HarnessArtifact`
- `authority_log`: ports/paths/network/processes touched
- `verifier`: `artifact_exists`, `schema_valid`, `claim_check`

## Aliases

The adapter accepts both short and long tool names:

- `nmap` → `nmap_scan`
- `searchsploit` → `searchsploit_query`
- `masscan` → `masscan_quick`
- `nikto` → `nikto_scan`
- `gobuster` → `gobuster_scan`
- `sqlmap` → `sqlmap_scan`
- `tshark` → `tshark_capture`

## Artifacts

All executions are recorded under:

```
/home/starwreck/kali-kimi-interface/results/<session_id>.json
```

Each file includes a top-level `integrity` block with SHA-256 and byte count, so Hermes can verify the artifact before making operator-facing claims.

## Notes

- No Kimi in the loop
- 152 registered tools, 78 installed
- Governance layer is additive; existing safety controls remain active
- `orchestrator.py` remains available for Kimi-driven workflows
