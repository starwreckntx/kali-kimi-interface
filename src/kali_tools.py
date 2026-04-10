#!/usr/bin/env python3
"""
Kali Linux Security Tool Adapter for Claw Harness

This module provides safe, structured access to Kali Linux penetration testing
tools through the claw harness tool registry. All commands are validated to
prevent injection attacks and outputs are parsed to JSON for LLM consumption.

Author: IRP Methodologies / PurpBox
Classification: IRP Operational Tool
"""

from __future__ import annotations

import json
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class SecurityToolResult:
    """Result container for security tool execution."""
    tool: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    parsed_output: Dict[str, Any]
    duration_ms: int
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Serialize result to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class SecurityToolError(Exception):
    """Custom exception for security tool errors."""
    pass


class KaliToolAdapter:
    """
    Adapter for Kali Linux penetration testing tools.
    
    Provides safe wrappers around common security tools with:
    - Input validation to prevent command injection
    - Structured output parsing
    - Timeout handling
    - Rate limiting support
    """
    
    # Known tool paths on Kali Linux
    TOOL_PATHS: Dict[str, str] = {
        'nmap': '/usr/bin/nmap',
        'sqlmap': '/usr/bin/sqlmap',
        'gobuster': '/usr/bin/gobuster',
        'dirb': '/usr/bin/dirb',
        'nikto': '/usr/bin/nikto',
        'masscan': '/usr/bin/masscan',
        'hydra': '/usr/bin/hydra',
        'john': '/usr/sbin/john',
        'aircrack-ng': '/usr/bin/aircrack-ng',
        'wpscan': '/usr/bin/wpscan',
        'ffuf': '/usr/bin/ffuf',
        'wfuzz': '/usr/bin/wfuzz',
    }
    
    # Characters that could enable command injection
    DANGEROUS_CHARS: set = {';', '&', '|', '`', '$', '(', ')', '<', '>', '\\', '\n', '{', '}'}
    
    # Default wordlists on Kali
    WORDLISTS: Dict[str, str] = {
        'dirb_common': '/usr/share/wordlists/dirb/common.txt',
        'dirb_big': '/usr/share/wordlists/dirb/big.txt',
        'rockyou': '/usr/share/wordlists/rockyou.txt',
        'nmap_vulns': '/usr/share/nmap/scripts/vulners.nse',
    }
    
    def __init__(self, timeout: int = 300, max_output_size: int = 50000):
        """
        Initialize the adapter.
        
        Args:
            timeout: Default command timeout in seconds
            max_output_size: Maximum output size to capture (bytes)
        """
        self.timeout = timeout
        self.max_output_size = max_output_size
        self._last_scan_time: Optional[float] = None
        self._rate_limit_seconds = 1  # Minimum seconds between scans
    
    def _validate_target(self, target: str) -> str:
        """
        Validate target string to prevent command injection.
        
        Args:
            target: Target host/IP/URL
            
        Returns:
            Validated target string
            
        Raises:
            SecurityToolError: If target contains dangerous characters
        """
        if not target or not isinstance(target, str):
            raise SecurityToolError("Target must be a non-empty string")
        
        if any(c in target for c in self.DANGEROUS_CHARS):
            raise SecurityToolError(
                f"Target contains forbidden characters. "
                f"Blocked characters: {self.DANGEROUS_CHARS}"
            )
        
        # Basic IP/CIDR validation pattern
        # Allows: IPs, hostnames, CIDR ranges
        # Blocks: shell commands
        return target.strip()
    
    def _check_rate_limit(self) -> None:
        """Check if rate limit allows another scan."""
        if self._last_scan_time is not None:
            elapsed = time.time() - self._last_scan_time
            if elapsed < self._rate_limit_seconds:
                raise SecurityToolError(
                    f"Rate limit: wait {self._rate_limit_seconds - elapsed:.1f}s"
                )
        self._last_scan_time = time.time()
    
    def _execute_tool(
        self, 
        tool: str, 
        cmd: List[str],
        custom_timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """
        Execute a security tool with safety measures.
        
        Args:
            tool: Tool name
            cmd: Command array (for subprocess)
            custom_timeout: Optional custom timeout override
            
        Returns:
            SecurityToolResult with execution results
        """
        from datetime import datetime
        
        start = time.time()
        timeout = custom_timeout or self.timeout
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            raise SecurityToolError(f"Command timed out after {timeout}s")
        except FileNotFoundError:
            raise SecurityToolError(f"Tool not found: {tool}")
        except Exception as e:
            raise SecurityToolError(f"Execution failed: {e}")
        
        duration_ms = int((time.time() - start) * 1000)
        
        # Truncate output if too large
        stdout = result.stdout[:self.max_output_size]
        stderr = result.stderr[:self.max_output_size]
        
        # Parse output based on tool
        parsed = self._parse_output(tool, stdout, stderr, result.returncode)
        
        return SecurityToolResult(
            tool=tool,
            command=' '.join(cmd),
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
            parsed_output=parsed,
            duration_ms=duration_ms,
            timestamp=datetime.now().isoformat()
        )
    
    def _parse_output(
        self, 
        tool: str, 
        stdout: str, 
        stderr: str,
        returncode: int
    ) -> Dict[str, Any]:
        """
        Parse tool output to structured format.
        
        Args:
            tool: Tool name
            stdout: Standard output
            stderr: Standard error
            returncode: Process exit code
            
        Returns:
            Dictionary with parsed results
        """
        parsed = {
            'success': returncode == 0,
            'exit_code': returncode,
            'summary': '',
            'findings': [],
            'raw_preview': stdout[:2000] if stdout else '',
        }
        
        if tool == 'nmap':
            parsed.update(self._parse_nmap_output(stdout))
        elif tool == 'sqlmap':
            parsed.update(self._parse_sqlmap_output(stdout, stderr))
        elif tool == 'gobuster':
            parsed.update(self._parse_gobuster_output(stdout))
        elif tool == 'nikto':
            parsed.update(self._parse_nikto_output(stdout))
        
        return parsed
    
    def _parse_nmap_output(self, output: str) -> Dict[str, Any]:
        """Parse nmap XML output."""
        try:
            if not output.strip().startswith('<?xml'):
                return {'format': 'text', 'hosts': []}
            
            root = ET.fromstring(output)
            hosts = []
            
            for host in root.findall('.//host'):
                host_data = {
                    'status': host.find('status').get('state') if host.find('status') is not None else 'unknown',
                    'addresses': [],
                    'hostnames': [],
                    'ports': []
                }
                
                for addr in host.findall('.//address'):
                    host_data['addresses'].append({
                        'addr': addr.get('addr'),
                        'type': addr.get('addrtype')
                    })
                
                for hostname in host.findall('.//hostname'):
                    host_data['hostnames'].append(hostname.get('name'))
                
                for port in host.findall('.//port'):
                    port_data = {
                        'port': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': port.find('state').get('state') if port.find('state') is not None else 'unknown',
                        'service': {}
                    }
                    service = port.find('service')
                    if service is not None:
                        port_data['service'] = {
                            'name': service.get('name'),
                            'product': service.get('product'),
                            'version': service.get('version')
                        }
                    host_data['ports'].append(port_data)
                
                hosts.append(host_data)
            
            return {
                'format': 'xml',
                'hosts': hosts,
                'host_count': len(hosts)
            }
        except ET.ParseError:
            return {'format': 'text', 'hosts': [], 'error': 'XML parse failed'}
    
    def _parse_sqlmap_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse sqlmap output for findings."""
        findings = []
        
        lines = (stdout + stderr).split('\n')
        for line in lines:
            if 'injection point' in line.lower() or 'parameter' in line.lower():
                findings.append({'type': 'injection_point', 'detail': line.strip()})
            elif 'database management system' in line.lower():
                findings.append({'type': 'dbms_detected', 'detail': line.strip()})
        
        return {
            'vulnerable': len(findings) > 0,
            'findings': findings,
            'full_output': stdout[:5000]
        }
    
    def _parse_gobuster_output(self, output: str) -> Dict[str, Any]:
        """Parse gobuster directory enumeration output."""
        findings = []
        
        for line in output.split('\n'):
            if line.startswith('/') or 'Status:' in line or 'Size:' in line:
                parts = line.split()
                if len(parts) >= 2:
                    findings.append({
                        'path': parts[0] if parts[0].startswith('/') else 'unknown',
                        'status': next((p for p in parts if p.isdigit()), 'unknown'),
                        'raw': line.strip()
                    })
        
        return {
            'directories_found': len(findings),
            'findings': findings[:100]  # Limit results
        }
    
    def _parse_nikto_output(self, output: str) -> Dict[str, Any]:
        """Parse Nikto vulnerability scan output."""
        findings = []
        
        for line in output.split('\n'):
            if line.startswith('+') and not line.startswith('++'):
                findings.append({'vulnerability': line[1:].strip()})
        
        return {
            'vulnerabilities_found': len(findings),
            'findings': findings
        }
    
    # ============== Public Tool Methods ==============
    
    def nmap_scan(
        self,
        target: str,
        scan_type: str = 'syn',
        ports: Optional[str] = None,
        flags: str = '',
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """
        Execute nmap network scan.
        
        Args:
            target: Target IP, hostname, or CIDR range
            scan_type: One of 'syn', 'connect', 'udp', 'comprehensive', 'vuln'
            ports: Port range (e.g., '1-65535', '80,443')
            flags: Additional nmap flags (validated)
            timeout: Optional timeout override
            
        Returns:
            SecurityToolResult with scan results
        """
        self._check_rate_limit()
        target = self._validate_target(target)
        
        # Build command array
        cmd = [self.TOOL_PATHS['nmap'], '-oX', '-']
        
        # Scan type flags
        scan_flags = {
            'syn': ['-sS'],
            'connect': ['-sT'],
            'udp': ['-sU'],
            'comprehensive': ['-sS', '-sV', '-sC', '-O', '--osscan-limit'],
            'vuln': ['--script', 'vuln'],
            'fast': ['-F'],
        }
        
        flags_list = scan_flags.get(scan_type, ['-sS'])
        
        # Handle conflicting flags: -F and -p don't work together
        if scan_type == 'fast' and ports:
            # If ports specified with fast, use --top-ports instead
            flags_list = ['-sS', '--top-ports', str(ports) if ports.isdigit() else '100']
        else:
            cmd.extend(flags_list)
        
        if ports and scan_type != 'fast':
            validated_ports = self._validate_target(ports)  # Reuse validation
            cmd.extend(['-p', validated_ports])
        
        if flags:
            # Validate and split flags carefully
            for flag in flags.split():
                if flag.startswith('-') and not any(c in flag for c in self.DANGEROUS_CHARS):
                    cmd.append(flag)
        
        cmd.append(target)
        
        return self._execute_tool('nmap', cmd, timeout)
    
    def sqlmap_scan(
        self,
        target: str,
        level: int = 1,
        risk: int = 1,
        batch: bool = True,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """
        Execute sqlmap SQL injection scan.
        
        Args:
            target: Target URL with parameters
            level: Test level (1-5)
            risk: Risk level (1-3)
            batch: Non-interactive mode
            timeout: Optional timeout override
            
        Returns:
            SecurityToolResult with scan results
        """
        self._check_rate_limit()
        target = self._validate_target(target)
        
        cmd = [
            self.TOOL_PATHS['sqlmap'],
            '-u', target,
            '--level', str(min(max(level, 1), 5)),
            '--risk', str(min(max(risk, 1), 3))
        ]
        
        if batch:
            cmd.append('--batch')
        
        return self._execute_tool('sqlmap', cmd, timeout)
    
    def gobuster_scan(
        self,
        url: str,
        mode: str = 'dir',
        wordlist: Optional[str] = None,
        threads: int = 50,
        extensions: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """
        Execute gobuster directory/file enumeration.
        
        Args:
            url: Target URL
            mode: 'dir', 'dns', 'fuzz', or 's3'
            wordlist: Path to wordlist (default: dirb common)
            threads: Number of concurrent threads
            extensions: File extensions to search (e.g., 'php,txt,html')
            timeout: Optional timeout override
            
        Returns:
            SecurityToolResult with enumeration results
        """
        self._check_rate_limit()
        url = self._validate_target(url)
        
        cmd = [self.TOOL_PATHS['gobuster'], mode, '-u', url]
        
        # Wordlist
        wordlist_path = wordlist or self.WORDLISTS['dirb_common']
        if Path(wordlist_path).exists():
            cmd.extend(['-w', wordlist_path])
        else:
            raise SecurityToolError(f"Wordlist not found: {wordlist_path}")
        
        cmd.extend(['-t', str(min(max(threads, 1), 100))])
        
        if extensions and mode == 'dir':
            cmd.extend(['-x', self._validate_target(extensions)])
        
        return self._execute_tool('gobuster', cmd, timeout)
    
    def nikto_scan(
        self,
        host: str,
        port: Optional[int] = None,
        ssl: bool = False,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """
        Execute Nikto web vulnerability scan.
        
        Args:
            host: Target host
            port: Target port (default: 80/443)
            ssl: Use HTTPS
            timeout: Optional timeout override
            
        Returns:
            SecurityToolResult with vulnerability findings
        """
        self._check_rate_limit()
        host = self._validate_target(host)
        
        cmd = [self.TOOL_PATHS['nikto'], '-h', host]
        
        if port:
            cmd.extend(['-p', str(port)])
        if ssl:
            cmd.append('-ssl')
        
        return self._execute_tool('nikto', cmd, timeout)
    
    def quick_recon(
        self,
        target: str,
        ports: str = 'top100'
    ) -> Dict[str, Any]:
        """
        Quick reconnaissance combining multiple tools.
        
        Args:
            target: Target host
            ports: 'top100' or custom range
            
        Returns:
            Combined reconnaissance results
        """
        port_map = {
            'top100': '-F',
            'top1000': '--top-ports 1000',
            'all': '-p-'
        }
        
        # Run fast nmap scan
        nmap_result = self.nmap_scan(
            target=target,
            scan_type='syn',
            flags=port_map.get(ports, '-F'),
            timeout=120
        )
        
        return {
            'target': target,
            'nmap': nmap_result.to_dict(),
            'summary': {
                'scan_time_ms': nmap_result.duration_ms,
                'hosts_found': nmap_result.parsed_output.get('host_count', 0),
                'success': nmap_result.returncode == 0
            }
        }


def main():
    """CLI entry point for testing."""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Kali Tool Adapter')
    parser.add_argument('tool', choices=['nmap', 'sqlmap', 'gobuster', 'nikto', 'recon'])
    parser.add_argument('target', help='Target host/URL')
    parser.add_argument('--type', '-t', help='Scan type')
    parser.add_argument('--ports', '-p', help='Port range')
    parser.add_argument('--output', '-o', help='Output file')
    
    args = parser.parse_args()
    
    adapter = KaliToolAdapter()
    
    try:
        if args.tool == 'nmap':
            result = adapter.nmap_scan(args.target, args.type or 'syn', args.ports)
        elif args.tool == 'sqlmap':
            result = adapter.sqlmap_scan(args.target)
        elif args.tool == 'gobuster':
            result = adapter.gobuster_scan(args.target)
        elif args.tool == 'nikto':
            result = adapter.nikto_scan(args.target)
        elif args.tool == 'recon':
            result_dict = adapter.quick_recon(args.target, args.ports or 'top100')
            print(json.dumps(result_dict, indent=2))
            return
        else:
            print(f"Unknown tool: {args.tool}", file=sys.stderr)
            sys.exit(1)
        
        output = result.to_json()
        
        if args.output:
            Path(args.output).write_text(output)
            print(f"Results written to {args.output}")
        else:
            print(output)
            
    except SecurityToolError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
