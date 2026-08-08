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
        'tshark': '/usr/bin/tshark',
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
        """Enforce minimum interval between scans by sleeping if needed."""
        if self._last_scan_time is not None:
            elapsed = time.time() - self._last_scan_time
            wait = self._rate_limit_seconds - elapsed
            if wait > 0:
                time.sleep(wait)
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

        # If the governance engine pinned this binary's inode, execute the pinned fd via
        # /proc/self/fd (no path re-resolution) so the bytes attested are the bytes run.
        # Falls back to a normal path exec when no pin is active (standalone / read-only use).
        pin = None
        try:
            from governance.attestation import get_active_pin
            pin = get_active_pin()
        except Exception:
            pin = None

        try:
            if pin is not None and getattr(pin, "fd", None) is not None:
                result = pin.run(cmd, capture_output=True, text=True, timeout=timeout)
            else:
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

    # --- masscan / tshark under the same L2 discipline -------------------------------
    # These previously ran via direct subprocess.run in the orchestrator, bypassing the
    # adapter's validation, rate limit, timeout, and output truncation. They are now first
    # class adapter methods so they inherit _validate_target, _check_rate_limit, and
    # _execute_tool (argument arrays, no shell=True, timeout + truncation + parsing).

    MAX_MASSCAN_RATE: int = 100000   # packets/sec hard ceiling
    ALLOWED_TSHARK_INTERFACES = {'eth0', 'eth1', 'wlan0', 'wlan1', 'lo', 'any'}

    def masscan_scan(
        self,
        target: str,
        ports: str = '1-1000',
        rate: int = 1000,
        timeout: Optional[int] = None,
    ) -> SecurityToolResult:
        """Execute a masscan port scan with a hard rate ceiling.

        Raises SecurityToolError if the requested rate exceeds MAX_MASSCAN_RATE.
        """
        self._check_rate_limit()
        target = self._validate_target(target)
        ports = self._validate_target(str(ports))   # reuse the metachar/allowlist gate
        try:
            rate_int = int(rate)
        except (TypeError, ValueError):
            raise SecurityToolError(f"masscan rate must be an integer, got {rate!r}")
        if rate_int <= 0:
            raise SecurityToolError("masscan rate must be positive")
        if rate_int > self.MAX_MASSCAN_RATE:
            raise SecurityToolError(
                f"masscan rate {rate_int} exceeds MAX_MASSCAN_RATE {self.MAX_MASSCAN_RATE}"
            )

        path = self.TOOL_PATHS.get('masscan', 'masscan')
        cmd = [path, target, '-p', ports, '--rate', str(rate_int)]
        return self._execute_tool('masscan', cmd, timeout)

    def tshark_capture(
        self,
        interface: str = 'any',
        filter_expr: str = '',
        duration: int = 10,
        timeout: Optional[int] = None,
    ) -> SecurityToolResult:
        """Capture packets with tshark, bounded by an interface allowlist and a duration.

        Raises SecurityToolError if the interface is not in ALLOWED_TSHARK_INTERFACES.
        """
        self._check_rate_limit()
        if interface not in self.ALLOWED_TSHARK_INTERFACES:
            raise SecurityToolError(
                f"interface {interface!r} not in allowed set {sorted(self.ALLOWED_TSHARK_INTERFACES)}"
            )
        try:
            duration_int = int(duration)
        except (TypeError, ValueError):
            raise SecurityToolError(f"duration must be an integer, got {duration!r}")
        duration_int = max(1, min(duration_int, 300))   # 1..300s

        path = self.TOOL_PATHS.get('tshark', 'tshark')
        cmd = [path, '-i', interface, '-a', f'duration:{duration_int}', '-c', '100']
        if filter_expr:
            # Reuse the metachar/allowlist gate to reject shell-dangerous filter strings.
            filter_expr = self._validate_target(filter_expr)
            cmd.extend(['-f', filter_expr])
        # Give the subprocess a little headroom beyond the capture duration.
        return self._execute_tool('tshark', cmd, timeout or (duration_int + 10))

    # === PHASE 1 PROOF-OF-LIFE METHODS (14 categories) ===
    
    def dnsrecon_scan(
        self,
        domain: str,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute dnsrecon DNS enumeration."""
        self._check_rate_limit()
        domain = self._validate_target(domain)
        
        cmd = ['dnsrecon', '-d', domain]
        
        return self._execute_tool(
            tool='dnsrecon',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def unix_privesc_check(
        self,
        mode: str = 'standard',
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Run unix-privesc-check for privilege escalation vectors."""
        self._check_rate_limit()
        
        if mode not in ('standard', 'detailed'):
            raise SecurityToolError(f"Invalid mode: {mode}")
        
        cmd = ['unix-privesc-check', mode]
        
        return self._execute_tool(
            tool='unix-privesc-check',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def wpscan_scan(
        self,
        url: str,
        enumerate: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute wpscan WordPress vulnerability scan."""
        self._check_rate_limit()
        url = self._validate_target(url)
        
        cmd = ['wpscan', '--url', url, '--no-update']
        
        if enumerate:
            cmd.extend(['--enumerate', enumerate])
        
        return self._execute_tool(
            tool='wpscan',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def cewl_wordlist(
        self,
        url: str,
        depth: int = 2,
        min_length: int = 3,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Generate wordlist from URL using cewl."""
        self._check_rate_limit()
        url = self._validate_target(url)
        
        if not (1 <= depth <= 10):
            raise SecurityToolError("Depth must be 1-10")
        if not (1 <= min_length <= 50):
            raise SecurityToolError("min_length must be 1-50")
        
        cmd = ['cewl', '-d', str(depth), '-m', str(min_length), url]
        
        return self._execute_tool(
            tool='cewl',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def airmon_check(
        self,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Check wireless interfaces with airmon-ng."""
        self._check_rate_limit()
        
        cmd = ['airmon-ng']
        
        return self._execute_tool(
            tool='airmon-ng',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def tcpdump_list_interfaces(
        self,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """List network interfaces with tcpdump."""
        self._check_rate_limit()
        
        cmd = ['tcpdump', '-D']
        
        return self._execute_tool(
            tool='tcpdump',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def binwalk_scan(
        self,
        file_path: str,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Scan file for embedded signatures with binwalk."""
        self._check_rate_limit()
        
        path = Path(file_path)
        if not path.exists():
            raise SecurityToolError(f"File not found: {file_path}")
        
        cmd = ['binwalk', str(path)]
        
        return self._execute_tool(
            tool='binwalk',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def ltrace_trace(
        self,
        binary: str,
        args: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Trace library calls with ltrace."""
        self._check_rate_limit()
        binary = self._validate_target(binary)
        
        cmd = ['ltrace']
        if args:
            cmd.extend(args.split())
        cmd.append(binary)
        
        return self._execute_tool(
            tool='ltrace',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def searchsploit_query(
        self,
        term: str,
        case_sensitive: bool = False,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Search exploit database."""
        self._check_rate_limit()
        
        if any(c in term for c in self.DANGEROUS_CHARS):
            raise SecurityToolError("Invalid characters in search term")
        
        cmd = ['searchsploit']
        if case_sensitive:
            cmd.append('-c')
        cmd.append(term)
        
        return self._execute_tool(
            tool='searchsploit',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def weeman_phish(
        self,
        url: str,
        port: int = 8080,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Start weeman phishing server."""
        self._check_rate_limit()
        url = self._validate_target(url)
        
        if not (1 <= port <= 65535):
            raise SecurityToolError("Invalid port")
        
        cmd = ['weeman', '-u', url, '-p', str(port)]
        
        return self._execute_tool(
            tool='weeman',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def apktool_decompile(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Decompile APK with apktool."""
        self._check_rate_limit()
        
        path = Path(apk_path)
        if not path.exists():
            raise SecurityToolError(f"APK not found: {apk_path}")
        
        cmd = ['apktool', 'd', str(path)]
        if output_dir:
            cmd.extend(['-o', output_dir])
        
        return self._execute_tool(
            tool='apktool',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def steghide_info(
        self,
        file_path: str,
        passphrase: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Extract steganography info with steghide."""
        self._check_rate_limit()
        
        path = Path(file_path)
        if not path.exists():
            raise SecurityToolError(f"File not found: {file_path}")
        
        cmd = ['steghide', 'info', str(path)]
        if passphrase:
            cmd.extend(['-p', passphrase])
        
        return self._execute_tool(
            tool='steghide',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def recordmydesktop_capture(
        self,
        output_file: str,
        duration: int = 10,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Record desktop session."""
        self._check_rate_limit()
        
        if not (1 <= duration <= 300):
            raise SecurityToolError("Duration must be 1-300 seconds")
        
        cmd = ['recordmydesktop', '-o', output_file, '--duration', str(duration)]
        
        return self._execute_tool(
            tool='recordmydesktop',
            cmd=cmd,
            custom_timeout=timeout
        )
    
    def netcat_port_scan(
        self,
        target: str,
        port: int,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Port scan with netcat."""
        self._check_rate_limit()
        target = self._validate_target(target)
        
        if not (1 <= port <= 65535):
            raise SecurityToolError("Invalid port")
        
        cmd = ['nc', '-z', '-v', '-w', '2', target, str(port)]
        
        return self._execute_tool(
            tool='netcat',
            cmd=cmd,
            custom_timeout=timeout
        )



    def radare2_scan(
        self,
        file_path: str,
        command: str = 'iS',
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Run radare2 in batch mode on a binary."""
        cmd = ['radare2', '-q', '-c', command, file_path]
        return self._execute_tool(
            tool='radare2',
            cmd=cmd,
            custom_timeout=timeout
        )

    # --- WiFi Tools ---

    def aircrack_ng_crack(
        self,
        capture_file: str,
        wordlist: Optional[str] = None,
        bssid: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Crack WEP/WPA captured handshake with aircrack-ng.

        Args:
            capture_file: Path to .cap capture file
            wordlist: Path to wordlist for WPA cracking (default: rockyou)
            bssid: Filter by AP BSSID (optional)
            timeout: Optional timeout override
        """
        path = Path(capture_file)
        if not path.exists():
            raise SecurityToolError(f"Capture file not found: {capture_file}")

        cmd = ['aircrack-ng']

        if bssid:
            cmd.extend(['-b', self._validate_target(bssid)])

        wordlist_path = wordlist or self.WORDLISTS['rockyou']
        if Path(wordlist_path).exists():
            cmd.extend(['-w', wordlist_path])
        else:
            raise SecurityToolError(f"Wordlist not found: {wordlist_path}")

        cmd.append(str(path))
        return self._execute_tool('aircrack-ng', cmd, timeout)

    def airdecap_ng_decrypt(
        self,
        capture_file: str,
        bssid: Optional[str] = None,
        essid: Optional[str] = None,
        wep_key: Optional[str] = None,
        wpa_psk: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Decrypt WEP/WPA captured traffic with airdecap-ng.

        Args:
            capture_file: Path to .cap capture file
            bssid: AP BSSID (optional)
            essid: AP ESSID (optional)
            wep_key: WEP key for decryption
            wpa_psk: WPA PSK for decryption
            timeout: Optional timeout override
        """
        path = Path(capture_file)
        if not path.exists():
            raise SecurityToolError(f"Capture file not found: {capture_file}")

        cmd = ['airdecap-ng']

        if wep_key:
            cmd.extend(['-w', wep_key])
        if wpa_psk:
            cmd.extend(['-p', wpa_psk])
        if bssid:
            cmd.extend(['-b', self._validate_target(bssid)])
        if essid:
            cmd.extend(['-e', self._validate_target(essid)])

        cmd.append(str(path))
        return self._execute_tool('airdecap-ng', cmd, timeout)

    def aireplay_ng_attack(
        self,
        interface: str,
        attack_type: str = 'deauth',
        bssid: Optional[str] = None,
        target_mac: Optional[str] = None,
        count: int = 5,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute aireplay-ng wireless attack.

        Args:
            interface: Monitor-mode wireless interface
            attack_type: 'deauth', 'fakeauth', 'interactive', 'arpreplay',
                         'chopchop', 'fragment'
            bssid: Target AP BSSID
            target_mac: Client target MAC for directed attacks
            count: Number of deauth frames (0=continuous)
            timeout: Optional timeout override
        """
        attack_map = {
            'deauth': ['-0'],
            'fakeauth': ['-1'],
            'interactive': ['-2'],
            'arpreplay': ['-3'],
            'chopchop': ['-4'],
            'fragment': ['-5'],
        }
        cmd = ['aireplay-ng']

        flags = attack_map.get(attack_type, ['-0'])
        cmd.extend(flags)

        if attack_type == 'deauth':
            cmd.append(str(count))

        cmd.append(self._validate_target(interface))

        if bssid:
            cmd.extend(['-a', self._validate_target(bssid)])
        if target_mac:
            cmd.extend(['-c', self._validate_target(target_mac)])

        return self._execute_tool('aireplay-ng', cmd, timeout)

    def airmon_ng_manage(
        self,
        interface: str,
        action: str = 'start',
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Enable/disable monitor mode with airmon-ng.

        Args:
            interface: Wireless interface (e.g., wlan0)
            action: 'start' to enable monitor, 'stop' to disable
            timeout: Optional timeout override
        """
        if action not in ('start', 'stop', 'check'):
            raise SecurityToolError(
                f"Invalid action: {action}. Use 'start', 'stop', or 'check'"
            )

        cmd = ['airmon-ng']
        if action == 'check':
            cmd.extend(['check', 'kill'])
        else:
            cmd.append(action)
            cmd.append(self._validate_target(interface))

        return self._execute_tool('airmon-ng', cmd, timeout)

    def airodump_ng_capture(
        self,
        interface: str,
        bssid: Optional[str] = None,
        channel: Optional[int] = None,
        output_prefix: Optional[str] = None,
        write: bool = True,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Capture WiFi traffic with airodump-ng.

        Args:
            interface: Monitor-mode interface
            bssid: Filter by AP BSSID
            channel: Lock to specific channel
            output_prefix: Output file prefix
            write: Enable writing to pcap files
            timeout: Optional timeout override
        """
        cmd = ['airodump-ng']

        if write and output_prefix:
            cmd.extend(['-w', self._validate_target(output_prefix)])
        elif write:
            cmd.extend(['-w', '/tmp/airodump_capture'])

        if bssid:
            cmd.extend(['--bssid', self._validate_target(bssid)])
        if channel:
            cmd.extend(['-c', str(channel)])

        cmd.append(self._validate_target(interface))
        return self._execute_tool('airodump-ng', cmd, timeout)

    def eapmd5pass_crack(
        self,
        capture_file: str,
        wordlist: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Crack EAP-MD5 hashes from capture file.

        Args:
            capture_file: Path to pcap capture file
            wordlist: Path to wordlist (default: rockyou)
            timeout: Optional timeout override
        """
        path = Path(capture_file)
        if not path.exists():
            raise SecurityToolError(f"Capture file not found: {capture_file}")

        cmd = ['eapmd5pass']

        wordlist_path = wordlist or self.WORDLISTS['rockyou']
        if Path(wordlist_path).exists():
            cmd.extend(['-w', wordlist_path])
        else:
            raise SecurityToolError(f"Wordlist not found: {wordlist_path}")

        cmd.append(str(path))
        return self._execute_tool('eapmd5pass', cmd, timeout)

    # --- MITM Tools ---

    def bettercap_run(
        self,
        interface: str,
        target: Optional[str] = None,
        gateway: Optional[str] = None,
        commands: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute bettercap MITM framework.

        Args:
            interface: Network interface
            target: Target IP address
            gateway: Gateway IP address
            commands: Semicolon-separated caplet commands
            timeout: Optional timeout override
        """
        cmd = ['bettercap', '-iface', self._validate_target(interface)]

        if target and gateway:
            caplet = (
                f"set arp.spoof.targets {self._validate_target(target)}; "
                f"arp.spoof on; "
                f"net.sniff on"
            )
            if commands:
                caplet += f"; {commands}"
            cmd.extend(['-eval', caplet])
        elif commands:
            cmd.extend(['-eval', commands])

        return self._execute_tool('bettercap', cmd, timeout)

    def driftnet_capture(
        self,
        interface: str,
        output_dir: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Capture images from network traffic with driftnet.

        Args:
            interface: Network interface
            output_dir: Directory for captured images (default: /tmp/driftnet)
            timeout: Optional timeout override
        """
        cmd = ['driftnet', '-i', self._validate_target(interface)]

        out = output_dir or '/tmp/driftnet'
        cmd.extend(['-p', out])

        return self._execute_tool('driftnet', cmd, timeout)

    def ettercap_sniff(
        self,
        interface: str,
        target: Optional[str] = None,
        mode: str = 'bridged',
        plugins: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute ettercap MITM attack.

        Args:
            interface: Network interface
            target: Target specification (MAC/IP)
            mode: 'bridged' (full duplex) or 'unified' (half duplex)
            plugins: Comma-separated plugin list (e.g., 'dhcp_spoof,dns_spoof')
            timeout: Optional timeout override
        """
        cmd = ['ettercap', '-T', '-i', self._validate_target(interface)]

        if mode == 'bridged':
            cmd.append('-B')
        elif mode == 'unified':
            cmd.append('-U')

        if target:
            cmd.extend(['-t', self._validate_target(target)])

        if plugins:
            for plugin in plugins.split(','):
                cmd.extend(['-P', plugin.strip()])

        cmd.append('-q')
        return self._execute_tool('ettercap', cmd, timeout)

    def mitmproxy_run(
        self,
        interface: Optional[str] = None,
        port: int = 8080,
        mode: str = 'regular',
        script: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Start mitmproxy proxy for traffic interception.

        Args:
            interface: Listen interface
            port: Proxy port (default: 8080)
            mode: 'regular', 'transparent', 'socks5', or 'reverse'
            script: Path to mitmproxy addon script
            timeout: Optional timeout override
        """
        mode_map = {
            'regular': f'--mode regular --listen-port {port}',
            'transparent': f'--mode transparent --listen-port {port}',
            'socks5': f'--mode socks5 --listen-port {port}',
            'reverse': f'--mode reverse --listen-port {port}',
        }

        import shlex as _shlex
        cmd = ['mitmproxy'] + _shlex.split(
            mode_map.get(mode, mode_map['regular'])
        )

        if interface:
            cmd.extend([
                '--showhost', '--set',
                f'listen_host={self._validate_target(interface)}'
            ])

        if script:
            cmd.extend(['-s', script])

        return self._execute_tool('mitmproxy', cmd, timeout)

    # --- Forensics Tools ---

    def bulk_extractor_extract(
        self,
        input_file: str,
        output_dir: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Extract features from disk image with bulk_extractor.

        Args:
            input_file: Path to disk image or memory dump
            output_dir: Output directory (default: /tmp/bulk_extractor_<ts>)
            timeout: Optional timeout override
        """
        path = Path(input_file)
        if not path.exists():
            raise SecurityToolError(f"Input file not found: {input_file}")

        out_dir = output_dir or f'/tmp/bulk_extractor_{int(time.time())}'
        cmd = ['bulk_extractor', '-o', out_dir, str(path)]

        return self._execute_tool('bulk_extractor', cmd, timeout)

    def pdf_parser_analyze(
        self,
        input_file: str,
        object_id: Optional[int] = None,
        search: Optional[str] = None,
        stats: bool = False,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Analyze PDF structure for malicious content.

        Args:
            input_file: Path to PDF file
            object_id: Specific PDF object to analyze
            search: Search term within PDF objects
            stats: Show PDF statistics
            timeout: Optional timeout override
        """
        path = Path(input_file)
        if not path.exists():
            raise SecurityToolError(f"File not found: {input_file}")

        cmd = ['pdf-parser.py', str(path)]

        if object_id is not None:
            cmd.extend(['--object', str(object_id)])
        if search:
            cmd.extend(['--search', search])
        if stats:
            cmd.append('--stats')

        return self._execute_tool('pdf-parser', cmd, timeout)

    # --- Crypto Tools ---

    def hash_identifier_identify(
        self,
        hash_value: str,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Identify hash type from a hash string.

        Args:
            hash_value: Hash string to identify
            timeout: Optional timeout override
        """
        if any(c in hash_value for c in self.DANGEROUS_CHARS):
            raise SecurityToolError("Invalid characters in hash value")

        cmd = ['hash-identifier']
        start = time.time()
        try:
            result = subprocess.run(
                cmd,
                input=hash_value,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout
            )
        except subprocess.TimeoutExpired:
            raise SecurityToolError("hash-identifier timed out")
        except FileNotFoundError:
            raise SecurityToolError("Tool not found: hash-identifier")
        except Exception as e:
            raise SecurityToolError(f"Execution failed: {e}")

        duration_ms = int((time.time() - start) * 1000)
        from datetime import datetime
        stdout = result.stdout[:self.max_output_size]
        stderr = result.stderr[:self.max_output_size]

        return SecurityToolResult(
            tool='hash-identifier',
            command=f"echo '{hash_value}' | hash-identifier",
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
            parsed_output={
                'success': result.returncode == 0,
                'exit_code': result.returncode,
                'hash_value': hash_value,
                'raw_preview': stdout[:2000],
            },
            duration_ms=duration_ms,
            timestamp=datetime.now().isoformat()
        )

    # --- Network Tools ---

    def ike_scan_enum(
        self,
        target: str,
        port: int = 500,
        aggressive: bool = False,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Scan for IKE VPN endpoints with ike-scan.

        Args:
            target: Target IP or CIDR
            port: UDP port (default: 500)
            aggressive: Use aggressive mode
            timeout: Optional timeout override
        """
        target = self._validate_target(target)

        cmd = ['ike-scan']
        if aggressive:
            cmd.append('-A')
        cmd.extend(['-p', str(port)])
        cmd.append(target)

        return self._execute_tool('ike-scan', cmd, timeout)

    def iperf3_benchmark(
        self,
        target: str,
        port: int = 5201,
        duration: int = 10,
        protocol: str = 'tcp',
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Run iperf3 network performance benchmark.

        Args:
            target: Server IP address
            port: Server port (default: 5201)
            duration: Test duration in seconds
            protocol: 'tcp' or 'udp'
            timeout: Optional timeout override
        """
        target = self._validate_target(target)

        cmd = ['iperf3', '-c', target, '-p', str(port),
               '-t', str(duration)]

        if protocol == 'udp':
            cmd.append('-u')
            cmd.extend(['-b', '1G'])

        return self._execute_tool('iperf3', cmd, timeout)

    def p0f_fingerprint(
        self,
        interface: str,
        count: int = 100,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Passive OS fingerprinting with p0f.

        Args:
            interface: Network interface to listen on
            count: Number of packets to capture
            timeout: Optional timeout override
        """
        cmd = ['p0f', '-i', self._validate_target(interface)]

        if count > 0:
            cmd.extend(['-c', str(count)])

        return self._execute_tool('p0f', cmd, timeout)

    # --- Reverse Engineering ---

    def radare2_analyze(
        self,
        input_file: str,
        commands: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Run radare2 reverse engineering analysis.

        Args:
            input_file: Path to binary file
            commands: Semicolon-separated r2 commands (default: 'aaa;iS')
            timeout: Optional timeout override
        """
        path = Path(input_file)
        if not path.exists():
            raise SecurityToolError(f"File not found: {input_file}")

        r2_commands = commands or 'aaa;iS'
        cmd = ['radare2', '-q', '-c', r2_commands, str(path)]

        return self._execute_tool('radare2', cmd, timeout)

    # --- Android Tools ---

    def dex2jar_convert(
        self,
        input_file: str,
        output_file: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Convert DEX to JAR for analysis.

        Args:
            input_file: Path to .dex or .apk file
            output_file: Output JAR path (optional)
            timeout: Optional timeout override
        """
        path = Path(input_file)
        if not path.exists():
            raise SecurityToolError(f"File not found: {input_file}")

        cmd = ['d2j-dex2jar', str(path)]

        if output_file:
            cmd.extend(['-o', output_file])

        return self._execute_tool('dex2jar', cmd, timeout)

    # --- Web Tools ---

    def commix_exploit(
        self,
        url: str,
        level: int = 1,
        risk: int = 1,
        batch: bool = True,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Test for command injection with commix.

        Args:
            url: Target URL with injectable parameter
            level: Test level (1-3)
            risk: Risk level (1-3)
            batch: Non-interactive mode
            timeout: Optional timeout override
        """
        target = self._validate_target(url)

        cmd = ['commix', '-u', target,
               '--level', str(min(max(level, 1), 3)),
               '--risk', str(min(max(risk, 1), 3))]

        if batch:
            cmd.append('--batch')

        return self._execute_tool('commix', cmd, timeout)

    def wafw00f_detect(
        self,
        url: str,
        find_all: bool = False,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Detect web application firewalls with wafw00f.

        Args:
            url: Target URL
            find_all: Find all WAFs, not just the first
            timeout: Optional timeout override
        """
        target = self._validate_target(url)

        cmd = ['wafw00f', target]
        if find_all:
            cmd.append('-a')

        return self._execute_tool('wafw00f', cmd, timeout)

    def zaproxy_scan(
        self,
        target: str,
        scan_type: str = 'baseline',
        api_key: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute OWASP ZAP scan.

        Args:
            target: Target URL
            scan_type: 'baseline', 'full', or 'api'
            api_key: ZAP API key (optional)
            timeout: Optional timeout override
        """
        target = self._validate_target(target)

        if scan_type == 'api':
            cmd = ['zaproxy', '-cmd', '-quickurl', target,
                   '-quickout', '/tmp/zap_api_results.xml']
        elif scan_type == 'full':
            cmd = ['zaproxy', '-cmd', '-quickurl', target,
                   '-quickout', '/tmp/zap_full_results.xml',
                   '-config', 'scanner.maxScanDurationInMins=60']
        else:
            cmd = ['zaproxy', '-cmd', '-quickurl', target,
                   '-quickout', '/tmp/zap_baseline_results.xml']

        if api_key:
            cmd.extend(['-config', f'apikey={api_key}'])

        return self._execute_tool('zaproxy', cmd, timeout)

    # --- Payload Generation ---

    def msfvenom_generate(
        self,
        payload_type: str,
        lhost: str,
        lport: int,
        format: str = 'raw',
        output_file: Optional[str] = None,
        extra_options: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Generate Metasploit payloads with msfvenom.

        Args:
            payload_type: Payload (e.g., 'linux/x64/meterpreter/reverse_tcp')
            lhost: Listener host IP
            lport: Listener port
            format: Output format ('raw', 'exe', 'elf', 'c', 'python', etc.)
            output_file: Path to write payload
            extra_options: Additional options string (e.g., 'Encoder=x86/shikata_ga_nai')
            timeout: Optional timeout override
        """
        lhost = self._validate_target(lhost)
        if not (1 <= lport <= 65535):
            raise SecurityToolError("Invalid port")

        cmd = ['msfvenom', '-p', payload_type,
               f'LHOST={lhost}', f'LPORT={lport}',
               '-f', format]

        if extra_options:
            for opt in extra_options.split():
                cmd.append(opt)

        if output_file:
            cmd.extend(['-o', output_file])

        return self._execute_tool('msfvenom', cmd, timeout)

    # --- Wordlist Generation ---

    def cewl_generate(
        self,
        url: str,
        output_file: Optional[str] = None,
        depth: int = 2,
        min_length: int = 3,
        max_length: Optional[int] = None,
        emails_only: bool = False,
        lowercase: bool = True,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Generate wordlist from website with cewl.

        Args:
            url: Target URL to crawl
            output_file: Output wordlist path (default: stdout)
            depth: Crawl depth (1-10)
            min_length: Minimum word length
            max_length: Maximum word length (optional)
            emails_only: Extract emails only
            lowercase: Convert to lowercase
            timeout: Optional timeout override
        """
        target = self._validate_target(url)

        if not (1 <= depth <= 10):
            raise SecurityToolError("Depth must be 1-10")
        if not (1 <= min_length <= 50):
            raise SecurityToolError("min_length must be 1-50")

        cmd = ['cewl', '-d', str(depth), '-m', str(min_length)]

        if max_length:
            cmd.extend(['-M', str(max_length)])
        if emails_only:
            cmd.append('--email_file')
            cmd.append(output_file or '/tmp/cewl_emails.txt')
            return self._execute_tool('cewl', cmd, timeout)
        if lowercase:
            cmd.append('--lowercase')

        if output_file:
            cmd.extend(['-w', output_file])

        cmd.append(target)
        return self._execute_tool('cewl', cmd, timeout)

    # --- Privilege Escalation ---

    def linux_exploit_suggester_check(
        self,
        kernel_version: Optional[str] = None,
        sudo_check: bool = False,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Suggest potential Linux kernel exploits.

        Args:
            kernel_version: Kernel version string (auto-detected if omitted)
            sudo_check: Also check sudo misconfigurations
            timeout: Optional timeout override
        """
        cmd = ['linux-exploit-suggester.sh']

        if kernel_version:
            cmd.extend(['--uname', kernel_version])
        if sudo_check:
            cmd.append('--sudostring')

        return self._execute_tool('linux-exploit-suggester', cmd, timeout)

    # --- Vulnerability Scanning ---

    def openvas_scan(
        self,
        target: str,
        scan_config: str = 'Full and fast',
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute OpenVAS/GVM vulnerability scan.

        Args:
            target: Target IP or hostname
            scan_config: Scan configuration name
            timeout: Optional timeout override
        """
        target = self._validate_target(target)

        import tempfile
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.rc', delete=False
        ) as f:
            f.write(f"TARGET {target}\n")
            f.write("PORTS 1-65535\n")
            f.write("SCAN_FAMILY OpenVAS\n")
            f.write("EXECUTE\n")
            rc_file = f.name

        cmd = ['openvas', '--scan', rc_file]
        return self._execute_tool('openvas', cmd, timeout)

    def routersploit_exploit(
        self,
        target: str,
        module: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Test router/embedded device vulnerabilities.

        Args:
            target: Target IP address
            module: Specific exploit module path (optional)
            timeout: Optional timeout override
        """
        target = self._validate_target(target)

        if module:
            commands = (
                f"use {module}; set target {target}; run; exit"
            )
        else:
            commands = f"scan {target}; exit"

        cmd = ['rsf.py', '-c', commands]
        return self._execute_tool('routersploit', cmd, timeout)

    # --- OSINT Tools ---

    def recon_ng_recon(
        self,
        workspace: str = 'default',
        module: Optional[str] = None,
        source: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute OSINT reconnaissance with recon-ng.

        Args:
            workspace: Workspace name (default: 'default')
            module: Module to run (e.g., 'recon/domains-hosts/hackertarget')
            source: Target source for the module
            timeout: Optional timeout override
        """
        if module:
            if source:
                commands = (
                    f"workspaces select {workspace}; "
                    f"modules load {module}; "
                    f"options set SOURCE {source}; "
                    f"run; exit"
                )
            else:
                commands = (
                    f"workspaces select {workspace}; "
                    f"modules load {module}; "
                    f"run; exit"
                )
            cmd = ['recon-ng', '-r', commands]
        else:
            cmd = ['recon-ng', '-w', workspace, '--no-remote']

        return self._execute_tool('recon-ng', cmd, timeout)

    def spiderfoot_scan(
        self,
        target: str,
        modules: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute SpiderFoot OSINT automation.

        Args:
            target: Target domain, IP, or keyword
            modules: Comma-separated module list (optional, all if omitted)
            timeout: Optional timeout override
        """
        target = self._validate_target(target)

        cmd = ['spiderfoot', '-s', target]
        if modules:
            cmd.extend(['-m', modules])
        cmd.extend(['-t', ' DOMAIN_NAME,IP_ADDRESS'])

        return self._execute_tool('spiderfoot', cmd, timeout)

    def theHarvester_harvest(
        self,
        domain: str,
        source: str = 'google',
        limit: int = 100,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Gather emails, IPs, and subdomains with theHarvester.

        Args:
            domain: Target domain
            source: Data source ('google', 'bing', 'linkedin',
                     'dnsdumpster', 'shodan', 'crtsh', 'all')
            limit: Maximum results per source
            timeout: Optional timeout override
        """
        target = self._validate_target(domain)

        cmd = ['theHarvester', '-d', target,
               '-b', source, '-l', str(limit)]

        return self._execute_tool('theHarvester', cmd, timeout)

    # --- Social Engineering ---

    def setoolkit_attack(
        self,
        attack_type: str = '1',
        target: Optional[str] = None,
        url: Optional[str] = None,
        port: int = 80,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute Social-Engineering Toolkit attack vector.

        Args:
            attack_type: '1'=spear-phishing, '2'=website-attack,
                         '3'=infectious-media, '4'=payloads
            target: Target IP or email
            url: Cloned/attack URL
            port: Listener port
            timeout: Optional timeout override
        """
        if attack_type == '2':
            if not target:
                raise SecurityToolError(
                    "Target URL required for website attacks"
                )
            commands = (
                f"website; credential-attack; "
                f"web-clone {url or 'https://www.google.com'} {port}; "
                f"set_config PORT {port}"
            )
        elif attack_type == '1':
            commands = (
                "SET_CONFIG SELF-signed 0; "
                "set_config SELF_SIGNED_APPLE 0"
            )
        elif attack_type == '3':
            commands = "infectious-media-generator"
        elif attack_type == '4':
            commands = "payloads"
        else:
            raise SecurityToolError(f"Invalid attack_type: {attack_type}")

        cmd = ['setoolkit', '-c', commands]
        return self._execute_tool('setoolkit', cmd, timeout)

    def setoolkit_credential_harvest(
        self,
        url: str,
        port: int = 80,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Clone a website for credential harvesting with SET.

        Args:
            url: URL to clone
            port: Local server port (default: 80)
            timeout: Optional timeout override
        """
        target = self._validate_target(url)
        if not (1 <= port <= 65535):
            raise SecurityToolError("Invalid port")

        commands = (
            f"website; credential-attack; "
            f"web-clone {target} {port}"
        )
        cmd = ['setoolkit', '-c', commands]
        return self._execute_tool('setoolkit', cmd, timeout)

    def legion_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Execute Legion network vulnerability scanner.

        Args:
            target: Target IP or CIDR range
            ports: Port range to scan
            timeout: Optional timeout override
        """
        target = self._validate_target(target)

        cmd = ['legion', '--nogui', '--dest', target]
        if ports:
            cmd.extend(['--ports', ports])

        return self._execute_tool('legion', cmd, timeout)

    # --- Privilege Escalation Check ---

    def unix_privesc_check_full(
        self,
        mode: str = 'standard',
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Run unix-privesc-check for privilege escalation vectors.

        Args:
            mode: 'standard' or 'detailed'
            timeout: Optional timeout override
        """
        if mode not in ('standard', 'detailed'):
            raise SecurityToolError(
                f"Invalid mode: {mode}. Use 'standard' or 'detailed'"
            )

        cmd = ['unix-privesc-check', mode]
        return self._execute_tool('unix-privesc-check', cmd, timeout)

    # --- Steganography ---

    def openstego_embed(
        self,
        input_file: str,
        embed_file: str,
        output_file: str,
        password: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Embed hidden data with OpenStego steganography.

        Args:
            input_file: Cover file for embedding
            embed_file: File to embed
            output_file: Output stego file path
            password: Optional passphrase
            timeout: Optional timeout override
        """
        path = Path(input_file)
        if not path.exists():
            raise SecurityToolError(f"Cover file not found: {input_file}")

        embed_path = Path(embed_file)
        if not embed_path.exists():
            raise SecurityToolError(f"Embed file not found: {embed_file}")

        cmd = ['openstego', 'embed',
               '-cf', input_file,
               '-mf', embed_file,
               '-sf', output_file]

        if password:
            cmd.extend(['-p', password])

        return self._execute_tool('openstego', cmd, timeout)

    def openstego_extract(
        self,
        stego_file: str,
        output_dir: str,
        password: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Extract hidden data from steganographic file.

        Args:
            stego_file: Path to stego file
            output_dir: Output directory for extracted data
            password: Optional passphrase
            timeout: Optional timeout override
        """
        path = Path(stego_file)
        if not path.exists():
            raise SecurityToolError(f"Stego file not found: {stego_file}")

        cmd = ['openstego', 'extract',
               '-sf', stego_file,
               '-xd', output_dir]

        if password:
            cmd.extend(['-p', password])

        return self._execute_tool('openstego', cmd, timeout)

    # --- VPN Brute Force ---

    def thc_pptp_bruter_brute(
        self,
        target: str,
        wordlist: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> SecurityToolResult:
        """Brute force PPTP VPN credentials.

        Args:
            target: Target IP address
            wordlist: Path to wordlist (default: rockyou)
            timeout: Optional timeout override
        """
        target = self._validate_target(target)

        cmd = ['thc-pptp-bruter', target]

        wordlist_path = wordlist or self.WORDLISTS['rockyou']
        if Path(wordlist_path).exists():
            cmd.extend(['-w', wordlist_path])
        else:
            raise SecurityToolError(f"Wordlist not found: {wordlist_path}")

        return self._execute_tool('thc-pptp-bruter', cmd, timeout)


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