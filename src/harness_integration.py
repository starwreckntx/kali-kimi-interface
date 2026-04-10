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
