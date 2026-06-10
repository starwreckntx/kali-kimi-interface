#!/usr/bin/env python3
"""
Kali Kimi Orchestrator — AI-driven security assessment through KKI

Hermes delegates security tasks to Kimi, who decides which tools to run.
Kimi's tool calls are executed through the KKI harness, results fed back.

Usage:
    python3 orchestrator.py --target 192.168.1.0/24 --task "full recon"
    python3 orchestrator.py --target example.com --task "web vuln scan"
    python3 orchestrator.py --target 10.0.0.1 --task "port scan" --depth quick

Architecture:
    Operator → Hermes → Kimi (reasoning) → KKI harness (execution) → Kimi (analysis) → Hermes → Operator
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from harness_integration import SecurityToolExecutor
from tool_registry import VerifiableToolRegistry
from kali_tools import SecurityToolResult, SecurityToolError
from governance.engine import GovernedExecutor, GovernedResult
from governance.policy import PolicyEngine
from governance.consent import ConsentGate
from governance.audit import AuditLog


# Default working directory is the repository root (this file's directory), so the
# orchestrator runs out-of-the-box for anyone who has cloned the repo.
DEFAULT_WORK_DIR = Path(__file__).resolve().parent


def resolve_kimi_cli(explicit: Optional[str] = None) -> Optional[str]:
    """Locate an executable Kimi CLI binary.

    Resolution order (first executable match wins):
      1. An explicit path (e.g. the --kimi-cli flag)
      2. The KIMI_CLI environment variable
      3. ``kimi`` discovered on PATH
      4. ``~/.local/bin/kimi`` (the conventional pip --user install location)

    Returns the resolved absolute path, or ``None`` if no executable was found.
    """
    candidates = [
        explicit,
        os.environ.get("KIMI_CLI"),
        shutil.which("kimi"),
        str(Path.home() / ".local" / "bin" / "kimi"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser()
        if path.exists() and os.access(path, os.X_OK):
            return str(path.resolve())
    return None


@dataclass
class OrchestratorSession:
    """Tracks an orchestration session."""
    session_id: str
    target: str
    task: str
    depth: str  # quick, standard, deep
    started_at: str
    findings: List[Dict[str, Any]]
    tool_calls: List[Dict[str, Any]]
    kimi_session_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class KaliKimiOrchestrator:
    """
    Orchestrates Kali tools through Kimi's reasoning.
    
    Flow:
    1. Send task description + available tools to Kimi
    2. Kimi returns tool calls (JSON)
    3. Execute through KKI harness
    4. Feed results back to Kimi for analysis
    5. Kimi decides next tool or completes
    """
    
    AVAILABLE_TOOLS = {
        "nmap_scan": {
            "description": "Network scan - port discovery, OS detection, service enumeration",
            "params": {
                "target": "Target IP/hostname/CIDR (required)",
                "scan_type": "syn|connect|udp|comprehensive|vuln|fast",
                "ports": "Port range e.g. 1-1000, 80,443",
                "flags": "Additional nmap flags"
            }
        },
        "sqlmap_scan": {
            "description": "SQL injection vulnerability scan",
            "params": {
                "target": "Target URL with parameters (required)",
                "level": "Test level 1-5",
                "risk": "Risk level 1-3"
            }
        },
        "gobuster_scan": {
            "description": "Directory/file enumeration on web servers",
            "params": {
                "url": "Target URL (required)",
                "mode": "dir|dns|fuzz|s3",
                "threads": "Concurrent threads 1-100",
                "extensions": "File extensions e.g. php,txt,html"
            }
        },
        "nikto_scan": {
            "description": "Web server vulnerability scan",
            "params": {
                "host": "Target host (required)",
                "port": "Target port",
                "ssl": "Use HTTPS true/false"
            }
        },
        "quick_recon": {
            "description": "Quick reconnaissance - nmap + service detection",
            "params": {
                "target": "Target host/IP (required)",
                "ports": "top100|top1000|all"
            }
        },
        "masscan_quick": {
            "description": "Ultra-fast port scan (masscan wrapper)",
            "params": {
                "target": "Target IP/CIDR (required)",
                "ports": "Port range e.g. 1-65535",
                "rate": "Packets per second"
            }
        },
        "tshark_capture": {
            "description": "Network packet capture",
            "params": {
                "interface": "Network interface e.g. eth0",
                "duration": "Capture duration in seconds",
                "filter": "BPF filter expression"
            }
        }
    }
    
    def __init__(
        self,
        verbose: bool = False,
        kimi_cli: Optional[str] = None,
        work_dir: Optional[str] = None,
        governed: bool = True,
        executor: Any = None,
        network_scope: Optional[List[str]] = None,
        consent_prompt: Any = None,
        consent_timeout: float = 30.0,
        manifest: Optional[str] = None,
    ):
        self.verbose = verbose
        self.work_dir = str(Path(work_dir).expanduser().resolve()) if work_dir else str(DEFAULT_WORK_DIR)
        self.kimi_cli = resolve_kimi_cli(kimi_cli)
        # Route every tool call through the governance gate by default. Inject an executor
        # (e.g. a stub) for test isolation; pass governed=False only to bypass for tests.
        if executor is not None:
            self.executor = executor
        elif governed:
            # F4: a manifest engages the verifiable root of trust; without one the registry
            # falls back to trust-on-first-use and the engine logs a high-visibility warning.
            self.executor = GovernedExecutor(
                executor=SecurityToolExecutor(),
                registry=VerifiableToolRegistry(manifest=manifest),
                policy=PolicyEngine(network_scope=network_scope),
                consent=ConsentGate(prompt_fn=consent_prompt, timeout=consent_timeout),
                audit=AuditLog(),
            )
        else:
            self.executor = SecurityToolExecutor()
        # Dispatch decisions key off the *actual* executor type, not just the flag.
        self.governed = isinstance(self.executor, GovernedExecutor)
        self.sessions: Dict[str, OrchestratorSession] = {}

    def require_kimi(self) -> str:
        """Return the Kimi CLI path, raising a clear error if it is unavailable."""
        if not self.kimi_cli:
            raise SecurityToolError(
                "Kimi CLI not found. Install it and ensure `kimi` is on your PATH, "
                "set the KIMI_CLI environment variable to its full path, or pass "
                "--kimi-cli /path/to/kimi."
            )
        return self.kimi_cli

    def _call_kimi(self, prompt: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Call Kimi CLI with a prompt, return parsed response."""

        cmd = [self.require_kimi(), "--print", "--quiet", "--prompt", prompt, "-w", self.work_dir]
        if session_id:
            cmd.extend(["-r", session_id])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=self.work_dir
            )
            
            response = result.stdout.strip()
            
            # Try to extract JSON from response
            json_blocks = []
            
            # Strategy 1: Find ```json ... ``` fenced blocks
            fenced = re.findall(r'```(?:json)?\s*\n(.*?)```', response, re.DOTALL)
            for block in fenced:
                try:
                    json_blocks.append(json.loads(block.strip()))
                except json.JSONDecodeError:
                    pass
            
            # Strategy 2: Find outermost { } or [ ] blocks
            if not json_blocks:
                for start_char in ['{', '[']:
                    end_char = '}' if start_char == '{' else ']'
                    depth = 0
                    start_idx = None
                    for i, c in enumerate(response):
                        if c == start_char and start_idx is None:
                            start_idx = i
                            depth = 1
                        elif start_idx is not None:
                            if c == start_char:
                                depth += 1
                            elif c == end_char:
                                depth -= 1
                                if depth == 0:
                                    try:
                                        json_blocks.append(json.loads(response[start_idx:i+1]))
                                    except json.JSONDecodeError:
                                        pass
                                    start_idx = None
                                    break
            
            # Strategy 3: Brute force — find first { and try progressively
            if not json_blocks:
                idx = response.find('{')
                if idx >= 0:
                    for end in range(len(response), idx, -1):
                        try:
                            parsed = json.loads(response[idx:end])
                            json_blocks.append(parsed)
                            break
                        except json.JSONDecodeError:
                            continue
            
            return {
                "raw_response": response,
                "json_blocks": json_blocks,
                "has_tool_calls": len(json_blocks) > 0,
                "returncode": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {"raw_response": "TIMEOUT", "json_blocks": [], "has_tool_calls": False, "returncode": -1}
        except Exception as e:
            return {"raw_response": f"ERROR: {e}", "json_blocks": [], "has_tool_calls": False, "returncode": -1}
    
    def _build_initial_prompt(self, target: str, task: str, depth: str) -> str:
        """Build the initial prompt for Kimi."""
        
        tool_descriptions = "\n".join([
            f"  - {name}: {info['description']}\n    Params: {json.dumps(info['params'])}"
            for name, info in self.AVAILABLE_TOOLS.items()
        ])
        
        depth_instruction = {
            "quick": "Run minimal scans. 1-2 tool calls max. Focus on speed.",
            "standard": "Run thorough scans. 3-5 tool calls. Balance speed and coverage.",
            "deep": "Run exhaustive scans. No limit on tool calls. Leave no stone unturned."
        }.get(depth, "Run standard scans.")
        
        return f"""You are a cybersecurity assessment agent. Your job is to run security tools against a target and analyze results.

TARGET: {target}
TASK: {task}
DEPTH: {depth} — {depth_instruction}

AVAILABLE TOOLS:
{tool_descriptions}

IMPORTANT: You must respond with EXACTLY one JSON block per message. Format:
```json
{{
  "action": "tool_call",
  "tool": "tool_name",
  "params": {{"param1": "value1"}}
}}
```

OR when done:
```json
{{
  "action": "complete",
  "summary": "Your analysis summary here",
  "findings": [{{"severity": "high|medium|low|info", "title": "Finding title", "detail": "Description"}}]
}}
```

Start your assessment. Return your FIRST tool call as JSON now."""

    def _execute_tool_call(self, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool call. masscan/tshark are now first-class harness tools, so every
        tool — with no exceptions — goes through the executor (and, when governed, the full
        governance gate). There is no direct-subprocess wrapper path anymore."""

        tool_name = tool_call.get("tool", "")
        params = tool_call.get("params", {})

        if self.verbose:
            print(f"[ORCHESTRATOR] Executing: {tool_name} with {json.dumps(params)}")

        if self.governed:
            return self._governed_dispatch(tool_name, params)

        # Ungoverned path (test isolation only).
        try:
            return self.executor.execute(tool_name, params)
        except Exception as e:
            return {"error": str(e), "tool": tool_name, "success": False}

    def _governed_dispatch(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Run a tool through the governance gate (with optional snap-back) and normalize
        the GovernedResult to the dict shape the assessment loop already expects."""
        snap = self._snap_before(tool_name)
        gr = self.executor.execute(tool_name, params)
        if gr.allowed:
            self._snap_after(snap, success=True)
            result = dict(gr.result or {})
            result.setdefault("tool", tool_name)
            return result
        # Blocked by governance, or executed and failed — roll back any snapshot.
        self._snap_after(snap, success=False)
        return self._deny_dict(tool_name, gr)

    @staticmethod
    def _deny_dict(tool_name: str, gr: "GovernedResult") -> Dict[str, Any]:
        # Shaped like a SecurityToolResult error so the existing loop error path catches it
        # with no special-casing.
        return {
            "tool": tool_name,
            "error": gr.denial_reason or "blocked by governance",
            "success": False,
            "returncode": -1,
            "parsed_output": {},
            "governance": gr.to_dict(),
        }
    
    # --- snap-back recovery (MOD-045) ------------------------------------------------
    # Capture a reversible snapshot of the artifacts workspace before a governed tool
    # runs, so a failure or denial can roll back partial mutations. Deliberately scoped to
    # <work_dir>/workspace and NEVER the repo/source tree: snapshotting work_dir itself
    # (which defaults to the repo root) would copy the whole checkout incl. .git on every
    # call. In the current toolset most output is stdout-captured, so this is a safety net
    # for file-writing tools rather than a hot path.

    def _workspace_dir(self) -> Path:
        return Path(self.work_dir) / "workspace"

    def _create_snap(self, target_dir: Path) -> Optional[str]:
        """Copy target_dir to a sibling .snap. Refuses unsafe targets; returns snap path."""
        rp = target_dir.resolve()
        # Guard: never snapshot the repo root or any directory holding a VCS checkout.
        if rp == Path(self.work_dir).resolve() or (rp / ".git").exists():
            return None
        if not rp.exists():
            return None
        snap_path = f"{rp}.snap"
        if os.path.exists(snap_path):
            shutil.rmtree(snap_path)
        shutil.copytree(rp, snap_path)
        return snap_path

    def _restore_snap(self, target_dir: Path, snap_path: str) -> None:
        rp = target_dir.resolve()
        if rp.exists():
            shutil.rmtree(rp)
        os.rename(snap_path, str(rp))

    def _delete_snap(self, snap_path: str) -> None:
        if snap_path and os.path.exists(snap_path):
            shutil.rmtree(snap_path)

    @staticmethod
    def _hash_snap(snap_path: str) -> str:
        h = hashlib.sha256()
        h.update(snap_path.encode())
        mtime = os.path.getmtime(snap_path) if snap_path and os.path.exists(snap_path) else 0
        h.update(str(mtime).encode())
        return h.hexdigest()

    def _snap_before(self, tool_name: str) -> Optional[str]:
        """Snapshot the workspace for danger/workspace-write tools, after the consent gate
        has been reached but before execution. Returns the snap path, or None."""
        if not self.governed:
            return None
        permission = self.executor._permission_for(tool_name)
        if permission not in ("danger-full-access", "workspace-write"):
            return None
        ws = self._workspace_dir()
        snap = self._create_snap(ws)
        if snap:
            self.executor.audit.log_integrity({
                "event": "snap_created", "tool": tool_name,
                "workspace": str(ws), "snap_hash": self._hash_snap(snap),
            })
        return snap

    def _snap_after(self, snap_path: Optional[str], success: bool) -> None:
        if not snap_path:
            return
        ws = self._workspace_dir()
        if success:
            self._delete_snap(snap_path)
            self.executor.audit.log_integrity({"event": "snap_deleted", "status": "success"})
        else:
            self._restore_snap(ws, snap_path)
            self.executor.audit.log_integrity({"event": "snap_restored", "status": "rolled_back"})

    def run_assessment(self, target: str, task: str = "full recon", depth: str = "standard", max_rounds: int = 10) -> Dict[str, Any]:
        """
        Run a full AI-driven assessment.
        
        Returns session results with all findings.
        """
        
        # Fail fast with a clear message if the Kimi CLI is missing.
        self.require_kimi()

        session_id = f"kki-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        if self.governed:
            # Correlate the audit chain with this assessment session.
            self.executor.audit.session_id = session_id
        session = OrchestratorSession(
            session_id=session_id,
            target=target,
            task=task,
            depth=depth,
            started_at=datetime.now().isoformat(),
            findings=[],
            tool_calls=[]
        )
        self.sessions[session_id] = session
        
        print(f"\n{'='*60}")
        print(f"KALI-KIMI ORCHESTRATOR — Session {session_id}")
        print(f"Target: {target} | Task: {task} | Depth: {depth}")
        print(f"Kimi CLI: {self.kimi_cli} | Work dir: {self.work_dir}")
        print(f"{'='*60}\n")
        
        # Build initial prompt
        prompt = self._build_initial_prompt(target, task, depth)
        
        for round_num in range(1, max_rounds + 1):
            print(f"\n--- Round {round_num} ---")
            
            # Call Kimi
            response = self._call_kimi(prompt)
            
            if self.verbose:
                print(f"[KIMI RAW] {response['raw_response'][:500]}")
            
            # Check if Kimi is done
            if not response["has_tool_calls"]:
                print(f"[!] Kimi returned no JSON. Raw: {response['raw_response'][:200]}")
                # Ask Kimi to try again with JSON
                prompt = f"Previous response was not valid JSON. You MUST return a JSON block. Target: {target}. Last output: {response['raw_response'][:500]}"
                continue
            
            tool_call = response["json_blocks"][0]
            action = tool_call.get("action", "")
            
            if action == "complete":
                print(f"\n[✓] Assessment complete!")
                session.findings = tool_call.get("findings", [])
                
                summary = tool_call.get("summary", "No summary provided")
                print(f"\nSummary: {summary}")
                
                break
            
            elif action == "tool_call":
                tool_name = tool_call.get("tool", "unknown")
                print(f"[→] Kimi requests: {tool_name}")
                
                # Execute tool
                result = self._execute_tool_call(tool_call)
                
                # Record
                session.tool_calls.append({
                    "round": round_num,
                    "tool": tool_name,
                    "params": tool_call.get("params", {}),
                    "result_summary": {
                        "success": result.get("success", result.get("returncode", -1) == 0),
                        "exit_code": result.get("returncode", -1),
                        "duration_ms": result.get("duration_ms", 0)
                    }
                })
                
                # Build follow-up prompt with results
                result_summary = json.dumps({
                    "tool": result.get("tool", tool_name),
                    "success": result.get("success", result.get("returncode", -1) == 0),
                    "exit_code": result.get("returncode", -1),
                    "findings": result.get("parsed_output", {}).get("findings", []),
                    "hosts": result.get("parsed_output", {}).get("hosts", []),
                    "summary": result.get("parsed_output", {}).get("summary", ""),
                    "raw_preview": result.get("parsed_output", {}).get("raw_preview", result.get("stdout", "")[:3000])
                }, indent=2)[:8000]
                
                prompt = f"""Tool execution result:

{result_summary}

Based on these results, either:
1. Call another tool (return JSON with action: "tool_call")
2. Complete the assessment (return JSON with action: "complete", summary, and findings)

Target: {target} | Task: {task}
Return your decision as JSON now."""
                
                print(f"[←] {tool_name} completed: {'success' if result.get('success', result.get('returncode', -1) == 0) else 'failed'}")
            
            else:
                print(f"[!] Unknown action: {action}")
                break
        
        # Save session under the working directory's results/ folder
        output_file = Path(self.work_dir) / "results" / f"{session_id}.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(session.to_dict(), f, indent=2)
        print(f"\n[📁] Session saved: {output_file}")

        # Mnemosyne mirror: the signed audit chain + any boundary-consent pending actions.
        if self.governed:
            audit_dir = Path(self.work_dir) / "audit"
            audit_dir.mkdir(parents=True, exist_ok=True)
            chain_file = audit_dir / f"{session_id}.chain"
            self.executor.save_audit(str(chain_file))
            boundary = self.executor.session_report()["boundary_consent"]
            with open(audit_dir / f"{session_id}.pending", 'w') as f:
                json.dump(boundary, f, indent=2)
            print(f"[🔐] Audit chain saved: {chain_file}")

        return session.to_dict()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Kali-Kimi Orchestrator")
    parser.add_argument("--target", "-t", required=True, help="Target IP/hostname/CIDR/URL")
    parser.add_argument("--task", default="full recon", help="Task description")
    parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard")
    parser.add_argument("--max-rounds", type=int, default=10, help="Max orchestration rounds")
    parser.add_argument("--kimi-cli", help="Path to the Kimi CLI (overrides PATH / KIMI_CLI env var)")
    parser.add_argument("--work-dir", help="Working directory for Kimi (default: repo root)")
    parser.add_argument("--network-scope", action="append",
                        help="Allowed target CIDR for the governance scope gate (repeatable)")
    parser.add_argument("--manifest",
                        help="Known-good tool manifest (F4 root of trust); omit to fall back to TOFU")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    # Governance is always on from the CLI — there is no --ungoverned bypass flag. The
    # `governed` constructor parameter remains for in-process test injection only.
    try:
        orchestrator = KaliKimiOrchestrator(
            verbose=args.verbose,
            kimi_cli=args.kimi_cli,
            work_dir=args.work_dir,
            network_scope=args.network_scope,
            manifest=args.manifest,
        )
        result = orchestrator.run_assessment(
            target=args.target,
            task=args.task,
            depth=args.depth,
            max_rounds=args.max_rounds,
        )
    except SecurityToolError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
