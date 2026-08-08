#!/usr/bin/env python3
"""
Hermes Direct Dispatcher for Kali Kimi Interface

Replaces the Kimi-specific orchestrator with a Hermes-direct execution path.
Hermes plans; this module dispatches and executes.

Usage:
    python3 hermes_dispatcher.py --target 192.168.1.0/24 --task "full recon"
    python3 hermes_dispatcher.py --target example.com --task "web vuln scan" --depth quick
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from hermes_harness import HermesHarness, HarnessResult


WORK_DIR = Path("/home/starwreck/kali-kimi-interface")


def _telegram_config() -> Dict[str, str]:
    config_path = Path.home() / ".hermes" / "config.yaml"
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_HOME_CHANNEL", "")
    if config_path.exists():
        try:
            text = config_path.read_text()
            m = re.search(r"bot_token:\s*([^\s]+)", text)
            if m and not token:
                token = m.group(1)
            m = re.search(r"home_chat_id:\s*([^\s]+)", text)
            if m and not chat_id:
                chat_id = m.group(1)
        except Exception:
            pass
    return {"token": token, "chat_id": chat_id}


def _telegram_send(text: str) -> bool:
    cfg = _telegram_config()
    token = cfg.get("token")
    chat_id = cfg.get("chat_id")
    if not token or not chat_id:
        return False
    try:
        subprocess.run(
            [
                "curl", "-s", "-X", "POST",
                f"https://api.telegram.org/bot{token}/sendMessage",
                "-d", f"chat_id={chat_id}",
                "-d", f"text={text}",
            ],
            capture_output=True,
            timeout=15,
        )
        return True
    except Exception:
        return False


def _telegram_poll_y_n(timeout_seconds: int = 300) -> Optional[str]:
    cfg = _telegram_config()
    token = cfg.get("token")
    if not token:
        return None
    start = time.time()
    last_update_id = 0
    while time.time() - start < timeout_seconds:
        try:
            result = subprocess.run(
                [
                    "curl", "-s", "-X", "POST",
                    f"https://api.telegram.org/bot{token}/getUpdates",
                    "-d", f"offset={last_update_id + 1}",
                    "-d", "timeout=10",
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )
            data = json.loads(result.stdout)
            for update in data.get("result", []):
                last_update_id = update.get("update_id", last_update_id)
                msg = update.get("message") or update.get("channel_post") or {}
                text = (msg.get("text") or "").strip().upper()
                if text in ("Y", "N"):
                    return text
        except Exception:
            time.sleep(2)
            continue
        time.sleep(2)
    return None


@dataclass
class DispatchPhase:
    phase_id: str
    tool: str
    params: Dict[str, Any]
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None


class HermesDispatcher:
    """
    Direct dispatcher for Hermes.

    No Kimi. Hermes supplies the assessment plan as phases;
    this module executes them through the harness and records artifacts.
    """

    def __init__(self, governance: bool = True, verbose: bool = False, telegram_confirm: bool = False):
        self.governance = governance
        self.verbose = verbose
        self.telegram_confirm = telegram_confirm
        self.harness = HermesHarness(work_dir=WORK_DIR, governance=governance)

    def _confirm_danger_tier(self, tool: str, params: Dict[str, Any]) -> bool:
        spec = self.harness.executor.tools.get(tool)
        if not spec:
            return True
        permission = getattr(spec, "required_permission", "")
        if permission != "danger-full-access":
            return True
        if not self.telegram_confirm:
            return True

        target = params.get("target") or params.get("url") or params.get("host") or "unknown"
        prompt = (
            "DISPATCH-CONFIRM: {tool}\n"
            "target: {target}\n"
            "permission: {permission}\n"
            "Reply Y to authorize, N to reject. Auto-reject in 5 minutes."
        ).format(tool=tool, target=target, permission=permission)
        print("[!] Danger-tier tool requested. Sending Telegram confirmation...")
        sent = _telegram_send(prompt)
        if not sent:
            print("[!] Telegram confirmation failed. Blocking execution.")
            return False
        response = _telegram_poll_y_n(timeout_seconds=300)
        if response == "Y":
            print("[+] Operator confirmed via Telegram.")
            return True
        print(f"[-] Operator response: {response or 'TIMEOUT'}. Blocking execution.")
        return False

    def run_phases(self, phases: List[Dict[str, Any]], json_mode: bool = False) -> Dict[str, Any]:
        session_id = self.harness.session_id
        results: List[Dict[str, Any]] = []

        if not json_mode:
            print(f"\n{'='*60}")
            print(f"HERMES DISPATCHER — Session {session_id}")
            print(f"Governance: {self.governance}")
            print(f"Phases: {len(phases)}")
            print(f"{'='*60}\n")

        for idx, phase in enumerate(phases, start=1):
            tool = phase.get("tool")
            params = phase.get("params", {})

            if not json_mode:
                print(f"--- Phase {idx}: {tool} ---")

            if not tool:
                result = {
                    "phase": idx,
                    "status": "failed",
                    "error": "missing tool in phase",
                }
                results.append(result)
                continue

            if not self._confirm_danger_tier(tool, params):
                result = {
                    "phase": idx,
                    "tool": tool,
                    "status": "failed",
                    "error": "danger-tier tool blocked: operator confirmation required",
                    "verifier": {
                        "artifact_exists": False,
                        "schema_valid": False,
                        "claim_check": "blocked by operator confirmation gate",
                    },
                }
                results.append(result)
                if not json_mode:
                    print("[BLOCKED] Operator confirmation required.")
                continue

            try:
                harness_result = self.harness.execute(tool, params)
            except Exception as exc:
                result = {
                    "phase": idx,
                    "tool": tool,
                    "status": "failed",
                    "error": str(exc),
                }
                results.append(result)
                continue

            result = {
                "phase": idx,
                "tool": harness_result.tool,
                "status": harness_result.status,
                "returncode": harness_result.returncode,
                "duration_ms": harness_result.duration_ms,
                "command": harness_result.command,
                "verifier": harness_result.verifier,
                "artifacts": [asdict(a) for a in harness_result.artifacts],
                "parsed_output": harness_result.parsed_output,
            }
            results.append(result)

            if not json_mode:
                status_label = harness_result.status.upper()
                print(f"[{status_label}] {tool} | rc={harness_result.returncode} | {harness_result.duration_ms}ms")
                if harness_result.verifier.get("claim_check"):
                    print(f"Claim: {harness_result.verifier['claim_check']}")

        session_path = str(self.harness._session_file)
        return {
            "session_id": session_id,
            "governance": self.governance,
            "phases_total": len(phases),
            "phases_completed": sum(1 for r in results if r.get("status") == "success"),
            "results": results,
            "session_file": session_path,
        }

    def quick_recon(self, target: str) -> Dict[str, Any]:
        phases = [
            {
                "tool": "quick_recon",
                "params": {"target": target, "ports": "top1000"},
            }
        ]
        return self.run_phases(phases)

    def web_scan(self, target: str) -> Dict[str, Any]:
        phases = [
            {
                "tool": "whatweb",
                "params": {"url": target},
            },
            {
                "tool": "nikto_scan",
                "params": {"host": target, "ssl": str(target).startswith("https://")},
            },
        ]
        return self.run_phases(phases)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Hermes Direct Dispatcher")
    parser.add_argument("--target", "-t", required=True, help="Target IP/hostname/CIDR/URL")
    parser.add_argument("--task", default="full recon", help="Task description")
    parser.add_argument("--depth", choices=["quick", "standard", "deep"], default="standard")
    parser.add_argument("--governance", choices=["on", "off"], default="on", help="Governance toggle")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--phases", help="JSON file with phase list", default=None)
    parser.add_argument("--json", dest="json_mode", action="store_true", help="JSON-only output")
    parser.add_argument("--telegram-confirm", action="store_true", help="Confirm danger-tier via Telegram")
    args = parser.parse_args()

    governance = args.governance == "on"
    dispatcher = HermesDispatcher(
        governance=governance,
        verbose=args.verbose,
        telegram_confirm=args.telegram_confirm,
    )

    if args.phases:
        with open(args.phases) as f:
            phases = json.load(f)
        result = dispatcher.run_phases(phases, json_mode=args.json_mode)
    elif args.task == "full recon":
        result = dispatcher.quick_recon(args.target)
    elif args.task == "web scan":
        result = dispatcher.web_scan(args.target)
    else:
        result = dispatcher.quick_recon(args.target)

    if args.json_mode:
        print(json.dumps(result, indent=2, default=str))
    else:
        print("\n" + json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
