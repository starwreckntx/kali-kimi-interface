#!/usr/bin/env python3
"""
Claw Harness Integration for Kali Tools

This module integrates the Kali tool adapter with the claw harness
tool registry, enabling security tools to be called through the
harness's unified tool execution interface.

Usage:
    from harness_integration import SecurityToolExecutor
    
    executor = SecurityToolExecutor()
    result = executor.execute('nmap_scan', {
        'target': '192.168.1.1',
        'scan_type': 'syn',
        'ports': '1-1000'
    })
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Callable

try:
    from .kali_tools import KaliToolAdapter, SecurityToolResult, SecurityToolError
except ImportError:
    from kali_tools import KaliToolAdapter, SecurityToolResult, SecurityToolError


@dataclass
class ToolSpec:
    """Tool specification for harness registry."""
    name: str
    description: str
    input_schema: Dict[str, Any]
    required_permission: str  # 'read-only', 'workspace-write', 'danger-full-access'
    handler: Callable


class SecurityToolExecutor:
    """
    Executor for security tools compatible with claw harness.
    
    Provides a unified interface that matches the harness's tool
    execution patterns while wrapping Kali Linux security tools.
    """
    
    # Permission levels aligned with harness
    PERMISSION_READ_ONLY = 'read-only'
    PERMISSION_WORKSPACE_WRITE = 'workspace-write'
    PERMISSION_DANGER_FULL_ACCESS = 'danger-full-access'
    
    def __init__(self):
        self.adapter = KaliToolAdapter()
        self._register_tools()
    
    def _register_tools(self) -> None:
        """Register all security tools with specifications."""
        self.tools: Dict[str, ToolSpec] = {}
        
        # Nmap scan tool
        self.tools['nmap_scan'] = ToolSpec(
            name='nmap_scan',
            description='Execute nmap network scans against targets',
            input_schema={
                'type': 'object',
                'properties': {
                    'target': {
                        'type': 'string',
                        'description': 'Target IP, hostname, or CIDR range'
                    },
                    'scan_type': {
                        'type': 'string',
                        'enum': ['syn', 'connect', 'udp', 'comprehensive', 'vuln', 'fast'],
                        'default': 'syn',
                        'description': 'Type of scan to perform'
                    },
                    'ports': {
                        'type': 'string',
                        'description': 'Port range (e.g., "1-65535", "80,443", "top100")'
                    },
                    'flags': {
                        'type': 'string',
                        'description': 'Additional nmap flags'
                    },
                    'timeout': {
                        'type': 'integer',
                        'minimum': 1,
                        'maximum': 3600,
                        'description': 'Timeout in seconds'
                    }
                },
                'required': ['target'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_nmap_scan
        )
        
        # SQLMap scan tool
        self.tools['sqlmap_scan'] = ToolSpec(
            name='sqlmap_scan',
            description='Test for SQL injection vulnerabilities',
            input_schema={
                'type': 'object',
                'properties': {
                    'target': {
                        'type': 'string',
                        'description': 'Target URL with parameters'
                    },
                    'level': {
                        'type': 'integer',
                        'minimum': 1,
                        'maximum': 5,
                        'default': 1,
                        'description': 'Test level (1-5)'
                    },
                    'risk': {
                        'type': 'integer',
                        'minimum': 1,
                        'maximum': 3,
                        'default': 1,
                        'description': 'Risk level (1-3)'
                    },
                    'batch': {
                        'type': 'boolean',
                        'default': True,
                        'description': 'Non-interactive mode'
                    },
                    'timeout': {
                        'type': 'integer',
                        'minimum': 1,
                        'maximum': 3600
                    }
                },
                'required': ['target'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_sqlmap_scan
        )
        
        # Gobuster directory enumeration
        self.tools['gobuster_scan'] = ToolSpec(
            name='gobuster_scan',
            description='Enumerate directories and files on web servers',
            input_schema={
                'type': 'object',
                'properties': {
                    'url': {
                        'type': 'string',
                        'description': 'Target URL'
                    },
                    'mode': {
                        'type': 'string',
                        'enum': ['dir', 'dns', 'fuzz', 's3'],
                        'default': 'dir',
                        'description': 'Enumeration mode'
                    },
                    'wordlist': {
                        'type': 'string',
                        'description': 'Path to wordlist file'
                    },
                    'threads': {
                        'type': 'integer',
                        'minimum': 1,
                        'maximum': 100,
                        'default': 50,
                        'description': 'Number of concurrent threads'
                    },
                    'extensions': {
                        'type': 'string',
                        'description': 'File extensions to search (e.g., "php,txt,html")'
                    },
                    'timeout': {
                        'type': 'integer',
                        'minimum': 1,
                        'maximum': 3600
                    }
                },
                'required': ['url'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_gobuster_scan
        )
        
        # Nikto vulnerability scan
        self.tools['nikto_scan'] = ToolSpec(
            name='nikto_scan',
            description='Scan web servers for known vulnerabilities',
            input_schema={
                'type': 'object',
                'properties': {
                    'host': {
                        'type': 'string',
                        'description': 'Target host'
                    },
                    'port': {
                        'type': 'integer',
                        'description': 'Target port (default: 80/443)'
                    },
                    'ssl': {
                        'type': 'boolean',
                        'default': False,
                        'description': 'Use HTTPS'
                    },
                    'timeout': {
                        'type': 'integer',
                        'minimum': 1,
                        'maximum': 3600
                    }
                },
                'required': ['host'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_nikto_scan
        )
        
        # Quick reconnaissance
        self.tools['quick_recon'] = ToolSpec(
            name='quick_recon',
            description='Perform quick reconnaissance on a target',
            input_schema={
                'type': 'object',
                'properties': {
                    'target': {
                        'type': 'string',
                        'description': 'Target host/IP'
                    },
                    'ports': {
                        'type': 'string',
                        'enum': ['top100', 'top1000', 'all'],
                        'default': 'top100',
                        'description': 'Port scope'
                    }
                },
                'required': ['target'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_quick_recon
        )

        # masscan / tshark — now first-class harness tools (previously direct-subprocess
        # wrappers in the orchestrator). Registered under the names Kimi already emits.
        self.tools['masscan_quick'] = ToolSpec(
            name='masscan_quick',
            description='High-speed port scan via masscan (rate-capped)',
            input_schema={
                'type': 'object',
                'properties': {
                    'target': {'type': 'string', 'description': 'Target IP/CIDR'},
                    'ports': {'type': 'string', 'description': 'Port range e.g. 1-65535'},
                    'rate': {'type': 'integer', 'minimum': 1, 'maximum': 100000,
                             'description': 'Packets/sec (hard ceiling 100000)'},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600},
                },
                'required': ['target'],
                'additionalProperties': False,
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_masscan_quick,
        )

        self.tools['tshark_capture'] = ToolSpec(
            name='tshark_capture',
            description='Bounded packet capture via tshark (interface allowlist + duration)',
            input_schema={
                'type': 'object',
                'properties': {
                    'interface': {'type': 'string',
                                  'enum': ['eth0', 'eth1', 'wlan0', 'wlan1', 'lo', 'any']},
                    'filter': {'type': 'string', 'description': 'BPF capture filter'},
                    'duration': {'type': 'integer', 'minimum': 1, 'maximum': 300},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600},
                },
                'required': [],
                'additionalProperties': False,
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_tshark_capture,
        )

    def _handle_masscan_quick(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        """Handle masscan execution under L2 discipline."""
        return self.adapter.masscan_scan(
            target=input_data['target'],
            ports=input_data.get('ports', '1-1000'),
            rate=input_data.get('rate', 1000),
            timeout=input_data.get('timeout'),
        )

    def _handle_tshark_capture(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        """Handle tshark capture under L2 discipline."""
        return self.adapter.tshark_capture(
            interface=input_data.get('interface', 'any'),
            filter_expr=input_data.get('filter', ''),
            duration=input_data.get('duration', 10),
            timeout=input_data.get('timeout'),
        )

        # === PHASE 1 PROOF-OF-LIFE REGISTRATIONS ===
        
        # Information Gathering
        self.tools['dnsrecon_scan'] = ToolSpec(
            name='dnsrecon_scan',
            description='DNS enumeration and reconnaissance',
            input_schema={
                'type': 'object',
                'properties': {
                    'domain': {'type': 'string', 'description': 'Target domain'},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['domain'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_dnsrecon_scan
        )
        
        # Vulnerability Analysis
        self.tools['unix_privesc_check'] = ToolSpec(
            name='unix_privesc_check',
            description='Check for Unix privilege escalation vectors',
            input_schema={
                'type': 'object',
                'properties': {
                    'mode': {'type': 'string', 'enum': ['standard', 'detailed'], 'default': 'standard'},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': [],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_unix_privesc_check
        )
        
        # Web Applications
        self.tools['wpscan_scan'] = ToolSpec(
            name='wpscan_scan',
            description='WordPress vulnerability scanner',
            input_schema={
                'type': 'object',
                'properties': {
                    'url': {'type': 'string', 'description': 'Target WordPress URL'},
                    'enumerate': {'type': 'string', 'description': 'Enumeration type'},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['url'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_wpscan_scan
        )
        
        # Password Attacks
        self.tools['cewl_wordlist'] = ToolSpec(
            name='cewl_wordlist',
            description='Generate custom wordlist from URL',
            input_schema={
                'type': 'object',
                'properties': {
                    'url': {'type': 'string', 'description': 'Target URL to spider'},
                    'depth': {'type': 'integer', 'minimum': 1, 'maximum': 10, 'default': 2},
                    'min_length': {'type': 'integer', 'minimum': 1, 'maximum': 50, 'default': 3},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['url'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_cewl_wordlist
        )
        
        # Wireless Attacks
        self.tools['airmon_check'] = ToolSpec(
            name='airmon_check',
            description='Check wireless interfaces',
            input_schema={
                'type': 'object',
                'properties': {
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': [],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_airmon_check
        )
        
        # Sniffing & Spoofing
        self.tools['tcpdump_list_interfaces'] = ToolSpec(
            name='tcpdump_list_interfaces',
            description='List network capture interfaces',
            input_schema={
                'type': 'object',
                'properties': {
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': [],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_READ_ONLY,
            handler=self._handle_tcpdump_list_interfaces
        )
        
        # Forensics
        self.tools['binwalk_scan'] = ToolSpec(
            name='binwalk_scan',
            description='Scan file for embedded signatures',
            input_schema={
                'type': 'object',
                'properties': {
                    'file_path': {'type': 'string', 'description': 'Path to file'},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['file_path'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_READ_ONLY,
            handler=self._handle_binwalk_scan
        )
        
        # Reverse Engineering
        self.tools['ltrace_trace'] = ToolSpec(
            name='ltrace_trace',
            description='Trace library calls in binary',
            input_schema={
                'type': 'object',
                'properties': {
                    'binary': {'type': 'string', 'description': 'Binary to trace'},
                    'args': {'type': 'string', 'description': 'Arguments to pass'},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['binary'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_WORKSPACE_WRITE,
            handler=self._handle_ltrace_trace
        )
        
        # Exploitation
        self.tools['searchsploit_query'] = ToolSpec(
            name='searchsploit_query',
            description='Search exploit database',
            input_schema={
                'type': 'object',
                'properties': {
                    'term': {'type': 'string', 'description': 'Search term'},
                    'case_sensitive': {'type': 'boolean', 'default': False},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['term'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_READ_ONLY,
            handler=self._handle_searchsploit_query
        )
        
        # Social Engineering
        self.tools['weeman_phish'] = ToolSpec(
            name='weeman_phish',
            description='Phishing server setup',
            input_schema={
                'type': 'object',
                'properties': {
                    'url': {'type': 'string', 'description': 'Target URL to clone'},
                    'port': {'type': 'integer', 'minimum': 1, 'maximum': 65535, 'default': 8080},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['url'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_weeman_phish
        )
        
        # Mobile Analysis
        self.tools['apktool_decompile'] = ToolSpec(
            name='apktool_decompile',
            description='Decompile Android APK',
            input_schema={
                'type': 'object',
                'properties': {
                    'apk_path': {'type': 'string', 'description': 'Path to APK'},
                    'output_dir': {'type': 'string', 'description': 'Output directory'},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['apk_path'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_WORKSPACE_WRITE,
            handler=self._handle_apktool_decompile
        )
        
        # Steganography
        self.tools['steghide_info'] = ToolSpec(
            name='steghide_info',
            description='Extract steganography info',
            input_schema={
                'type': 'object',
                'properties': {
                    'file_path': {'type': 'string', 'description': 'Path to file'},
                    'passphrase': {'type': 'string', 'description': 'Optional passphrase'},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['file_path'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_READ_ONLY,
            handler=self._handle_steghide_info
        )
        
        # Reporting
        self.tools['recordmydesktop_capture'] = ToolSpec(
            name='recordmydesktop_capture',
            description='Record desktop session',
            input_schema={
                'type': 'object',
                'properties': {
                    'output_file': {'type': 'string', 'description': 'Output file path'},
                    'duration': {'type': 'integer', 'minimum': 1, 'maximum': 300, 'default': 10},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['output_file'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_WORKSPACE_WRITE,
            handler=self._handle_recordmydesktop_capture
        )
        
        # System Services
        self.tools['netcat_port_scan'] = ToolSpec(
            name='netcat_port_scan',
            description='Port scan with netcat',
            input_schema={
                'type': 'object',
                'properties': {
                    'target': {'type': 'string', 'description': 'Target host'},
                    'port': {'type': 'integer', 'minimum': 1, 'maximum': 65535},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['target', 'port'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_DANGER_FULL_ACCESS,
            handler=self._handle_netcat_port_scan
        )
        
        self.tools['radare2_scan'] = ToolSpec(
            name='radare2_scan',
            description='Analyze binary sections with radare2 batch mode',
            input_schema={
                'type': 'object',
                'properties': {
                    'file_path': {'type': 'string', 'description': 'Binary file to analyze'},
                    'command': {'type': 'string', 'default': 'iS'},
                    'timeout': {'type': 'integer', 'minimum': 1, 'maximum': 3600}
                },
                'required': ['file_path'],
                'additionalProperties': False
            },
            required_permission=self.PERMISSION_READ_ONLY,
            handler=self._handle_radare2_scan
        )

    def _handle_nmap_scan(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        """Handle nmap scan execution."""
        return self.adapter.nmap_scan(
            target=input_data['target'],
            scan_type=input_data.get('scan_type', 'syn'),
            ports=input_data.get('ports'),
            flags=input_data.get('flags', ''),
            timeout=input_data.get('timeout')
        )
    
    def _handle_sqlmap_scan(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        """Handle sqlmap scan execution."""
        return self.adapter.sqlmap_scan(
            target=input_data['target'],
            level=input_data.get('level', 1),
            risk=input_data.get('risk', 1),
            batch=input_data.get('batch', True),
            timeout=input_data.get('timeout')
        )
    
    def _handle_gobuster_scan(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        """Handle gobuster scan execution."""
        return self.adapter.gobuster_scan(
            url=input_data['url'],
            mode=input_data.get('mode', 'dir'),
            wordlist=input_data.get('wordlist'),
            threads=input_data.get('threads', 50),
            extensions=input_data.get('extensions'),
            timeout=input_data.get('timeout')
        )
    
    def _handle_nikto_scan(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        """Handle nikto scan execution."""
        return self.adapter.nikto_scan(
            host=input_data['host'],
            port=input_data.get('port'),
            ssl=input_data.get('ssl', False),
            timeout=input_data.get('timeout')
        )
    
    def _handle_quick_recon(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle quick reconnaissance."""
        return self.adapter.quick_recon(
            target=input_data['target'],
            ports=input_data.get('ports', 'top100')
        )
    
    # === PHASE 1 HANDLERS ===
    
    def _handle_dnsrecon_scan(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.dnsrecon_scan(domain=input_data['domain'], timeout=input_data.get('timeout'))
    
    def _handle_unix_privesc_check(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.unix_privesc_check(mode=input_data.get('mode', 'standard'), timeout=input_data.get('timeout'))
    
    def _handle_wpscan_scan(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.wpscan_scan(url=input_data['url'], enumerate=input_data.get('enumerate'), timeout=input_data.get('timeout'))
    
    def _handle_cewl_wordlist(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.cewl_wordlist(url=input_data['url'], depth=input_data.get('depth', 2), min_length=input_data.get('min_length', 3), timeout=input_data.get('timeout'))
    
    def _handle_airmon_check(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.airmon_check(timeout=input_data.get('timeout'))
    
    def _handle_tcpdump_list_interfaces(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.tcpdump_list_interfaces(timeout=input_data.get('timeout'))
    
    def _handle_binwalk_scan(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.binwalk_scan(file_path=input_data['file_path'], timeout=input_data.get('timeout'))
    
    def _handle_ltrace_trace(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.ltrace_trace(binary=input_data['binary'], args=input_data.get('args'), timeout=input_data.get('timeout'))
    
    def _handle_searchsploit_query(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.searchsploit_query(term=input_data['term'], case_sensitive=input_data.get('case_sensitive', False), timeout=input_data.get('timeout'))
    
    def _handle_weeman_phish(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.weeman_phish(url=input_data['url'], port=input_data.get('port', 8080), timeout=input_data.get('timeout'))
    
    def _handle_apktool_decompile(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.apktool_decompile(apk_path=input_data['apk_path'], output_dir=input_data.get('output_dir'), timeout=input_data.get('timeout'))
    
    def _handle_steghide_info(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.steghide_info(file_path=input_data['file_path'], passphrase=input_data.get('passphrase'), timeout=input_data.get('timeout'))
    
    def _handle_recordmydesktop_capture(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.recordmydesktop_capture(output_file=input_data['output_file'], duration=input_data.get('duration', 10), timeout=input_data.get('timeout'))
    
    def _handle_netcat_port_scan(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.netcat_port_scan(target=input_data['target'], port=input_data['port'], timeout=input_data.get('timeout'))
    
    def _handle_radare2_scan(self, input_data: Dict[str, Any]) -> SecurityToolResult:
        return self.adapter.radare2_scan(file_path=input_data['file_path'], command=input_data.get('command', 'iS'), timeout=input_data.get('timeout'))
    
    def list_tools(self) -> Dict[str, Dict[str, Any]]:
        """
        List all available security tools.
        
        Returns:
            Dictionary of tool name -> specification
        """
        return {
            name: {
                'name': spec.name,
                'description': spec.description,
                'input_schema': spec.input_schema,
                'required_permission': spec.required_permission
            }
            for name, spec in self.tools.items()
        }
    
    def get_tool_spec(self, tool_name: str) -> Optional[ToolSpec]:
        """Get specification for a specific tool."""
        return self.tools.get(tool_name)
    
    def execute(self, tool_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a security tool.
        
        Args:
            tool_name: Name of the tool to execute
            input_data: Tool input parameters
            
        Returns:
            Execution result as dictionary
            
        Raises:
            SecurityToolError: If tool execution fails
            ValueError: If tool not found
        """
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        tool_spec = self.tools[tool_name]
        
        try:
            result = tool_spec.handler(input_data)
            
            # Convert result to dictionary
            if isinstance(result, SecurityToolResult):
                return result.to_dict()
            elif isinstance(result, dict):
                return result
            else:
                return {'result': str(result)}
                
        except SecurityToolError as e:
            return {
                'error': str(e),
                'tool': tool_name,
                'success': False
            }
        except Exception as e:
            return {
                'error': f"Unexpected error: {e}",
                'tool': tool_name,
                'success': False
            }
    
    def validate_input(self, tool_name: str, input_data: Dict[str, Any]) -> list:
        """
        Validate input data against tool schema.
        
        Args:
            tool_name: Name of the tool
            input_data: Input to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        if tool_name not in self.tools:
            return [f"Unknown tool: {tool_name}"]
        
        spec = self.tools[tool_name]
        schema = spec.input_schema
        errors = []
        
        # Check required fields
        required = schema.get('required', [])
        for field in required:
            if field not in input_data:
                errors.append(f"Missing required field: {field}")
        
        # Check property types
        properties = schema.get('properties', {})
        for field, value in input_data.items():
            if field in properties:
                prop_spec = properties[field]
                expected_type = prop_spec.get('type')
                
                if expected_type == 'string' and not isinstance(value, str):
                    errors.append(f"Field '{field}' must be a string")
                elif expected_type == 'integer' and not isinstance(value, int):
                    errors.append(f"Field '{field}' must be an integer")
                elif expected_type == 'boolean' and not isinstance(value, bool):
                    errors.append(f"Field '{field}' must be a boolean")
                
                # Check enum values
                if 'enum' in prop_spec and value not in prop_spec['enum']:
                    errors.append(
                        f"Field '{field}' must be one of: {prop_spec['enum']}"
                    )
        
        return errors


def main():
    """CLI entry point for testing integration."""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(
        description='Security Tool Executor - Claw Harness Integration'
    )
    parser.add_argument(
        '--list', '-l',
        action='store_true',
        help='List available tools'
    )
    parser.add_argument(
        '--tool', '-t',
        help='Tool name to execute'
    )
    parser.add_argument(
        '--input', '-i',
        help='Tool input as JSON string'
    )
    parser.add_argument(
        '--validate', '-v',
        action='store_true',
        help='Validate input without executing'
    )
    
    args = parser.parse_args()
    
    executor = SecurityToolExecutor()
    
    if args.list:
        tools = executor.list_tools()
        print(json.dumps(tools, indent=2))
        return
    
    if args.tool:
        if not args.input:
            print("Error: --input required when using --tool", file=sys.stderr)
            sys.exit(1)
        
        try:
            input_data = json.loads(args.input)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON input: {e}", file=sys.stderr)
            sys.exit(1)
        
        if args.validate:
            errors = executor.validate_input(args.tool, input_data)
            if errors:
                print(json.dumps({'valid': False, 'errors': errors}, indent=2))
                sys.exit(1)
            else:
                print(json.dumps({'valid': True}, indent=2))
                return
        
        result = executor.execute(args.tool, input_data)
        print(json.dumps(result, indent=2))
        return
    
    parser.print_help()


if __name__ == '__main__':
    main()
