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

import json
import re
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
from kali_tools import SecurityToolResult, SecurityToolError


KIMI_CLI = "/home/starwreck/.local/bin/kimi"
WORK_DIR = "/home/starwreck/kali-kimi-interface"


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
    
    def __init__(self, verbose: bool = False):
        self.executor = SecurityToolExecutor()
        self.verbose = verbose
        self.sessions: Dict[str, OrchestratorSession] = {}
    
    def _call_kimi(self, prompt: str, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Call Kimi CLI with a prompt, return parsed response."""
        
        cmd = [KIMI_CLI, "--print", "--quiet", "--prompt", prompt, "-w", WORK_DIR]
        if session_id:
            cmd.extend(["-r", session_id])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=WORK_DIR
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
        """Execute a tool call through the KKI harness."""
        
        tool_name = tool_call.get("tool", "")
        params = tool_call.get("params", {})
        
        if self.verbose:
            print(f"[ORCHESTRATOR] Executing: {tool_name} with {json.dumps(params)}")
        
        # Handle masscan wrapper (not in harness natively)
        if tool_name == "masscan_quick":
            return self._run_masscan(params)
        
        # Handle tshark wrapper
        if tool_name == "tshark_capture":
            return self._run_tshark(params)
        
        # Use harness for standard tools
        try:
            result = self.executor.execute(tool_name, params)
            return result
        except Exception as e:
            return {"error": str(e), "tool": tool_name, "success": False}
    
    def _run_masscan(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Wrapper for masscan."""
        target = params.get("target", "")
        ports = params.get("ports", "1-1000")
        rate = params.get("rate", "1000")
        
        try:
            result = subprocess.run(
                ["masscan", target, "-p", ports, "--rate", rate],
                capture_output=True, text=True, timeout=120
            )
            return {
                "tool": "masscan",
                "command": f"masscan {target} -p {ports} --rate {rate}",
                "returncode": result.returncode,
                "stdout": result.stdout[:50000],
                "stderr": result.stderr[:50000],
                "parsed_output": {"success": result.returncode == 0, "raw_preview": result.stdout[:5000]},
                "duration_ms": 0,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"error": str(e), "tool": "masscan", "success": False}
    
    def _run_tshark(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Wrapper for tshark."""
        interface = params.get("interface", "eth0")
        duration = params.get("duration", 10)
        bpf_filter = params.get("filter", "")
        
        try:
            cmd = ["tshark", "-i", interface, "-a", f"duration:{duration}", "-c", "100"]
            if bpf_filter:
                cmd.extend(["-f", bpf_filter])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=int(duration) + 10)
            return {
                "tool": "tshark",
                "command": " ".join(cmd),
                "returncode": result.returncode,
                "stdout": result.stdout[:50000],
                "stderr": result.stderr[:50000],
                "parsed_output": {"success": result.returncode == 0, "packet_count": len(result.stdout.strip().split('\n'))},
                "duration_ms": int(duration * 1000),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {"error": str(e), "tool": "tshark", "success": False}
    
    def run_assessment(self, target: str, task: str = "full recon", depth: str = "standard", max_rounds: int = 10) -> Dict[str, Any]:
        """
        Run a full AI-driven assessment.
        
        Returns session results with all findings.
        """
        
        session_id = f"kki-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
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
        
        # Save session
        output_file = f"/home/starwreck/kali-kimi-interface/results/{session_id}.json"
        Path(output_file).parent.mkdir(exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(session.to_dict(), f, indent=2)
        print(f"\n[📁] Session saved: {output_file}")
        
        return session.to_dict()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Kali-Kimi Orchestrator")
    parser.add_argument("--target", "-t", required=True, help="Target IP/hostname/CIDR/URL")
    parser.add_argument("--task", default="full recon", help="Task description")
    parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard")
    parser.add_argument("--max-rounds", type=int, default=10, help="Max orchestration rounds")
    parser.add_argument("--verbose", "-v", action="store_true")
    
    args = parser.parse_args()
    
    orchestrator = KaliKimiOrchestrator(verbose=args.verbose)
    result = orchestrator.run_assessment(
        target=args.target,
        task=args.task,
        depth=args.depth,
        max_rounds=args.max_rounds
    )
    
    print("\n" + json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
