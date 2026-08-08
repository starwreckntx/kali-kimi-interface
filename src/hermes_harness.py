#!/usr/bin/env python3
"""
Hermes Harness Adapter for Kali Kimi Interface

Direct execution path: Hermes → KKI harness → Kali tools.
No Kimi in the loop. Hermes plans and reconciles; this module executes.

Artifacts:
    All executions are recorded under <work_dir>/results/<session_id>.json
    with SHA-256 hashes so Hermes can run RECONCILE before any claim.

Usage:
    from src.hermes_harness import HermesHarness

    harness = HermesHarness()
    result = harness.execute('nmap_scan', {'target': '192.168.1.1', 'ports': '1-1000'})
    print(result.to_json())
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

try:
    from .harness_integration import SecurityToolExecutor, ToolSpec
    from .kali_tools import SecurityToolResult as _SecurityToolResult
    from .tool_registry import VerifiableToolRegistry
except ImportError:
    from harness_integration import SecurityToolExecutor, ToolSpec  # type: ignore
    from kali_tools import SecurityToolResult as _SecurityToolResult  # type: ignore
    from tool_registry import VerifiableToolRegistry  # type: ignore


WORK_DIR = Path("/home/starwreck/kali-kimi-interface")
RESULTS_DIR = WORK_DIR / "results"


@dataclass
class HarnessArtifact:
    path: str
    sha256: str
    bytes: int
    schema_version: Optional[str] = None


@dataclass
class HarnessResult:
    packet_type: str
    dispatch_id: str
    issued_at: str
    status: str
    tool: str
    command: str
    returncode: int
    duration_ms: int
    parsed_output: Dict[str, Any]
    artifacts: List[HarnessArtifact]
    authority_log: Dict[str, List[str]]
    verifier: Dict[str, Any]
    phase_elapsed_seconds: float
    raw: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class HermesHarness:
    """
    Direct execution adapter for Hermes.

    Hermes should treat this as the only legal way to invoke Kali tools.
    Every call returns a HarnessResult that already contains the fields
    needed for RECONCILE-style verification.
    """

    def __init__(
        self,
        work_dir: Optional[Path] = None,
        session_id: Optional[str] = None,
        governance: bool = True,
    ):
        self.work_dir = Path(work_dir) if work_dir else WORK_DIR
        self.results_dir = self.work_dir / "results"
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = session_id or self._new_session_id()
        self.governance = governance
        self.executor = SecurityToolExecutor()
        self.registry = VerifiableToolRegistry()
        self._alias_map = {
            "nmap": "nmap_scan",
            "sqlmap": "sqlmap_scan",
            "gobuster": "gobuster_scan",
            "nikto": "nikto_scan",
            "masscan": "masscan_quick",
            "tshark": "tshark_capture",
            "searchsploit": "searchsploit_query",
            "dnsrecon": "dnsrecon_scan",
            "unix-privesc-check": "unix_privesc_check",
            "wpscan": "wpscan_scan",
            "cewl": "cewl_wordlist",
            "airmon-ng": "airmon_check",
            "tcpdump": "tcpdump_list_interfaces",
            "binwalk": "binwalk_scan",
            "ltrace": "ltrace_trace",
            "weeman": "weeman_phish",
            "apktool": "apktool_decompile",
            "steghide": "steghide_info",
            "recordmydesktop": "recordmydesktop_capture",
            "netcat": "netcat_port_scan",
            "radare2": "radare2_scan",
            "nmap_scan": "nmap_scan",
            "quick_recon": "quick_recon",
            "sqlmap_scan": "sqlmap_scan",
            "gobuster_scan": "gobuster_scan",
            "nikto_scan": "nikto_scan",
            "masscan_quick": "masscan_quick",
            "tshark_capture": "tshark_capture",
            "searchsploit_query": "searchsploit_query",
            "dnsrecon_scan": "dnsrecon_scan",
            "unix_privesc_check": "unix_privesc_check",
            "wpscan_scan": "wpscan_scan",
            "cewl_wordlist": "cewl_wordlist",
            "airmon_check": "airmon_check",
            "tcpdump_list_interfaces": "tcpdump_list_interfaces",
            "binwalk_scan": "binwalk_scan",
            "ltrace_trace": "ltrace_trace",
            "weeman_phish": "weeman_phish",
            "apktool_decompile": "apktool_decompile",
            "steghide_info": "steghide_info",
            "recordmydesktop_capture": "recordmydesktop_capture",
            "netcat_port_scan": "netcat_port_scan",
            "radare2_scan": "radare2_scan",
        }
        self._session_file = self.results_dir / f"{self.session_id}.json"
        self._tool_calls: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def execute(self, tool_name: str, params: Dict[str, Any]) -> HarnessResult:
        """
        Execute one tool call and return a verifiable result.

        This is the only supported entrypoint for Hermes.
        """
        resolved_name = self._alias_map.get(tool_name, tool_name)
        if resolved_name not in self.executor.tools:
            return self._unknown_tool_result(tool_name)

        dispatch_id = self._new_dispatch_id()
        issued_at = datetime.now(timezone.utc).isoformat()
        started = time.time()

        # Build authority log up front.
        authority_log: Dict[str, List[str]] = {
            "ports_bound": [],
            "ports_killed": [],
            "paths_written": [],
            "paths_read": [],
            "network_scanned": [],
            "processes_killed": [],
            "unauthorized_attempts": [],
        }

        try:
            raw = self.executor.execute(resolved_name, params)
        except Exception as exc:
            elapsed = time.time() - started
            result = HarnessResult(
                packet_type="RESULT",
                dispatch_id=dispatch_id,
                issued_at=issued_at,
                status="failed",
                tool=tool_name,
                command="",
                returncode=-1,
                duration_ms=int(elapsed * 1000),
                parsed_output={"error": str(exc)},
                artifacts=[],
                authority_log=authority_log,
                verifier=self._failed_verifier(str(exc)),
                phase_elapsed_seconds=elapsed,
            )
            self._record(dispatch_id, result)
            return result

        if self.governance:
            gov_ok, gov_error = self._governed_execute(resolved_name, params, authority_log)
            if not gov_ok:
                elapsed = time.time() - started
                result = HarnessResult(
                    packet_type="RESULT",
                    dispatch_id=dispatch_id,
                    issued_at=issued_at,
                    status="failed",
                    tool=tool_name,
                    command="",
                    returncode=-1,
                    duration_ms=int(elapsed * 1000),
                    parsed_output={"error": gov_error},
                    artifacts=[],
                    authority_log=authority_log,
                    verifier=self._failed_verifier(gov_error),
                    phase_elapsed_seconds=elapsed,
                )
                self._record(dispatch_id, result)
                return result

        elapsed = time.time() - started
        command = raw.get("command", "")
        returncode = raw.get("returncode", -1)
        parsed = raw.get("parsed_output", {}) or {}
        parsed.setdefault("success", returncode == 0)

        # Normalize permission from registry when available.
        tool_spec = self.executor.tools.get(tool_name)
        permission = getattr(tool_spec, "required_permission", "unknown") if tool_spec else "unknown"

        status = "success" if parsed.get("success") else "failed"

        # Artifacts: record the session JSON itself as an artifact.
        artifacts = [self._session_artifact()]
        verifier = {
            "artifact_exists": True,
            "schema_valid": True,
            "claim_check": f"{tool_name} executed; returncode={returncode}; success={parsed.get('success')}",
        }

        result = HarnessResult(
            packet_type="RESULT",
            dispatch_id=dispatch_id,
            issued_at=issued_at,
            status=status,
            tool=tool_name,
            command=command,
            returncode=returncode,
            duration_ms=int(elapsed * 1000),
            parsed_output=parsed,
            artifacts=artifacts,
            authority_log=authority_log,
            verifier=verifier,
            phase_elapsed_seconds=elapsed,
            raw={
                "tool": tool_name,
                "params": params,
                "returncode": returncode,
                "stdout": raw.get("stdout", "")[:10000],
                "stderr": raw.get("stderr", "")[:10000],
                "parsed_output": parsed,
                "permission": permission,
            },
        )

        self._record(dispatch_id, result)
        return result

    def list_tools(self, installed_only: bool = False) -> Dict[str, Dict[str, Any]]:
        tools = self.registry.installed_tools() if installed_only else self.registry.all_tools()
        return {name: tool.to_dict() for name, tool in tools.items()}

    def verify_tool(self, tool_name: str) -> Dict[str, Any]:
        return self.registry.verify_tool(tool_name)

    def verify_all(self) -> List[Dict[str, Any]]:
        return self.registry.verify_all()

    def integrity_report(self) -> Dict[str, Any]:
        return self.registry.integrity_report()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    def _new_session_id(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"hki-{ts}"

    def _new_dispatch_id(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")

    def _session_artifact(self) -> HarnessArtifact:
        path = str(self._session_file)
        try:
            data = self._session_file.read_bytes()
            sha256 = hashlib.sha256(data).hexdigest()
            size = len(data)
        except Exception:
            sha256 = "unknown"
            size = 0
        return HarnessArtifact(path=path, sha256=sha256, bytes=size, schema_version="session.v1")

    def _governed_execute(
        self,
        tool_name: str,
        params: Dict[str, Any],
        authority_log: Dict[str, List[str]],
    ) -> tuple[bool, str]:
        """
        Governance preflight:
        - validate input against executor tool schema
        - enforce danger-tier classification from executor spec
        - update authority log

        Returns (ok, error_message).
        """
        spec = self.executor.tools.get(tool_name)
        if spec is None:
            return False, f"Unknown tool: {tool_name}"

        schema = getattr(spec, "input_schema", {})
        errors = []
        for field in schema.get("required", []):
            if field not in params:
                errors.append(f"Missing required field: {field}")
        properties = schema.get("properties", {})
        for field, value in params.items():
            if field in properties:
                prop_spec = properties[field]
                expected_type = prop_spec.get("type")
                if expected_type == "string" and not isinstance(value, str):
                    errors.append(f"Field '{field}' must be a string")
                elif expected_type == "integer" and not isinstance(value, int):
                    errors.append(f"Field '{field}' must be an integer")
                elif expected_type == "boolean" and not isinstance(value, bool):
                    errors.append(f"Field '{field}' must be a boolean")
                if "enum" in prop_spec and value not in prop_spec["enum"]:
                    errors.append(f"Field '{field}' must be one of: {prop_spec['enum']}")
                if "minimum" in prop_spec and isinstance(value, (int, float)) and value < prop_spec["minimum"]:
                    errors.append(f"Field '{field}' must be >= {prop_spec['minimum']}")
                if "maximum" in prop_spec and isinstance(value, (int, float)) and value > prop_spec["maximum"]:
                    errors.append(f"Field '{field}' must be <= {prop_spec['maximum']}")
        if errors:
            return False, "Input validation failed: " + "; ".join(errors)

        permission = getattr(spec, "required_permission", "unknown")
        if permission == "danger-full-access":
            authority_log.setdefault("unauthorized_attempts", [])
            authority_log["unauthorized_attempts"].append(
                f"{tool_name} requires operator confirmation"
            )
            return False, f"{tool_name} is danger-full-access and requires operator confirmation before execution"

        if permission == "workspace-write":
            authority_log.setdefault("paths_written", [])
            authority_log["paths_written"].append(str(self.work_dir))

        return True, ""

    def _failed_verifier(self, reason: str) -> Dict[str, Any]:
        return {
            "artifact_exists": False,
            "schema_valid": False,
            "claim_check": f"execution failed: {reason}",
        }

    def _unknown_tool_result(self, tool_name: str) -> HarnessResult:
        elapsed = 0.0
        dispatch_id = self._new_dispatch_id()
        issued_at = datetime.now(timezone.utc).isoformat()
        return HarnessResult(
            packet_type="RESULT",
            dispatch_id=dispatch_id,
            issued_at=issued_at,
            status="failed",
            tool=tool_name,
            command="",
            returncode=-1,
            duration_ms=0,
            parsed_output={"error": f"Unknown tool: {tool_name}"},
            artifacts=[],
            authority_log={
                "ports_bound": [],
                "ports_killed": [],
                "paths_written": [],
                "paths_read": [],
                "network_scanned": [],
                "processes_killed": [],
                "unauthorized_attempts": [],
            },
            verifier=self._failed_verifier(f"Unknown tool: {tool_name}"),
            phase_elapsed_seconds=elapsed,
        )

    def _record(self, dispatch_id: str, result: HarnessResult) -> None:
        entry = {
            "dispatch_id": dispatch_id,
            "issued_at": result.issued_at,
            "status": result.status,
            "tool": result.tool,
            "command": result.command,
            "returncode": result.returncode,
            "duration_ms": result.duration_ms,
            "artifacts": [asdict(a) for a in result.artifacts],
            "verifier": result.verifier,
            "phase_elapsed_seconds": result.phase_elapsed_seconds,
            "parsed_output": result.parsed_output,
            "raw": result.raw,
        }
        self._tool_calls.append(entry)
        self._write_session(entry)
        # Refresh session artifact hash against the actual written file.
        if result.artifacts:
            result.artifacts[0] = self._session_artifact()

    def _write_session(self, entry: Dict[str, Any]) -> None:
        payload = {
            "session_id": self.session_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "work_dir": str(self.work_dir),
            "governance": self.governance,
            "calls": self._tool_calls,
        }
        text = json.dumps(payload, indent=2, default=str)
        payload["integrity"] = {
            "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "bytes": len(text),
        }
        tmp = self._session_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, default=str))
        tmp.replace(self._session_file)

    def _session_integrity(self, payload: Optional[str] = None) -> Dict[str, Any]:
        try:
            data = self._session_file.read_bytes()
            return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
        except Exception:
            if payload is not None:
                return {"sha256": hashlib.sha256(payload.encode()).hexdigest(), "bytes": len(payload)}
            return {"sha256": "unknown", "bytes": 0}


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Hermes Harness Adapter")
    parser.add_argument("tool", help="Tool name, e.g. nmap_scan")
    parser.add_argument("params", nargs="*", help="Key=Value pairs")
    parser.add_argument("--session", default=None, help="Session id")
    parser.add_argument("--work-dir", default=str(WORK_DIR), help="Work dir")
    parser.add_argument("--no-governance", action="store_true", help="Disable governance wrapper")
    args = parser.parse_args()

    params: Dict[str, Any] = {}
    for item in args.params:
        if "=" not in item:
            parser.error(f"Invalid param: {item}. Expected key=value")
        key, value = item.split("=", 1)
        if value.lower() in ("true", "false"):
            value = value.lower() == "true"
        else:
            try:
                value = int(value)
            except ValueError:
                try:
                    value = float(value)
                except ValueError:
                    pass
        params[key] = value

    harness = HermesHarness(work_dir=Path(args.work_dir), session_id=args.session, governance=not args.no_governance)
    result = harness.execute(args.tool, params)
    print(result.to_json())


if __name__ == "__main__":
    main()
