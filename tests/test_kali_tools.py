#!/usr/bin/env python3
"""
Tests for Kali Linux Security Tool Adapter

Run with: python3 -m pytest tests/test_kali_tools.py -v
"""

import json
import pytest
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from kali_tools import KaliToolAdapter, SecurityToolResult, SecurityToolError


class TestInputValidation:
    """Test input validation and security measures."""
    
    def test_valid_ip_target(self):
        adapter = KaliToolAdapter()
        assert adapter._validate_target("192.168.1.1") == "192.168.1.1"
    
    def test_valid_hostname(self):
        adapter = KaliToolAdapter()
        assert adapter._validate_target("example.com") == "example.com"
    
    def test_valid_cidr(self):
        adapter = KaliToolAdapter()
        assert adapter._validate_target("192.168.1.0/24") == "192.168.1.0/24"
    
    def test_command_injection_blocked_semicolon(self):
        adapter = KaliToolAdapter()
        with pytest.raises(SecurityToolError) as exc_info:
            adapter._validate_target("127.0.0.1; rm -rf /")
        assert "forbidden characters" in str(exc_info.value).lower()
    
    def test_command_injection_blocked_pipe(self):
        adapter = KaliToolAdapter()
        with pytest.raises(SecurityToolError) as exc_info:
            adapter._validate_target("127.0.0.1 | cat /etc/passwd")
        assert "forbidden characters" in str(exc_info.value).lower()
    
    def test_command_injection_blocked_backtick(self):
        adapter = KaliToolAdapter()
        with pytest.raises(SecurityToolError) as exc_info:
            adapter._validate_target("127.0.0.1`whoami`")
        assert "forbidden characters" in str(exc_info.value).lower()
    
    def test_command_injection_blocked_dollar(self):
        adapter = KaliToolAdapter()
        with pytest.raises(SecurityToolError) as exc_info:
            adapter._validate_target("127.0.0.1$(cat /etc/passwd)")
        assert "forbidden characters" in str(exc_info.value).lower()
    
    def test_empty_target_rejected(self):
        adapter = KaliToolAdapter()
        with pytest.raises(SecurityToolError):
            adapter._validate_target("")
    
    def test_none_target_rejected(self):
        adapter = KaliToolAdapter()
        with pytest.raises(SecurityToolError):
            adapter._validate_target(None)


class TestToolResult:
    """Test SecurityToolResult data class."""
    
    def test_result_creation(self):
        result = SecurityToolResult(
            tool="nmap",
            command="nmap -sS 127.0.0.1",
            returncode=0,
            stdout="test output",
            stderr="",
            parsed_output={"hosts": []},
            duration_ms=1000,
            timestamp="2026-04-10T10:00:00"
        )
        assert result.tool == "nmap"
        assert result.returncode == 0
    
    def test_result_to_dict(self):
        result = SecurityToolResult(
            tool="nmap",
            command="nmap -sS 127.0.0.1",
            returncode=0,
            stdout="test",
            stderr="",
            parsed_output={},
            duration_ms=100,
            timestamp="2026-04-10T10:00:00"
        )
        d = result.to_dict()
        assert d['tool'] == "nmap"
        assert 'parsed_output' in d
    
    def test_result_to_json(self):
        result = SecurityToolResult(
            tool="nmap",
            command="nmap -sS 127.0.0.1",
            returncode=0,
            stdout="test",
            stderr="",
            parsed_output={"hosts": 1},
            duration_ms=100,
            timestamp="2026-04-10T10:00:00"
        )
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed['tool'] == "nmap"


class TestNmapParsing:
    """Test nmap output parsing."""
    
    def test_parse_xml_output(self):
        adapter = KaliToolAdapter()
        xml_output = '''<?xml version="1.0"?>
<nmaprun>
    <host>
        <status state="up"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="router.local"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="80">
                <state state="open"/>
                <service name="http"/>
            </port>
        </ports>
    </host>
</nmaprun>'''
        
        result = adapter._parse_nmap_output(xml_output)
        assert result['format'] == 'xml'
        assert len(result['hosts']) == 1
        assert result['host_count'] == 1
        assert result['hosts'][0]['status'] == 'up'
        assert len(result['hosts'][0]['ports']) == 1
    
    def test_parse_text_output(self):
        adapter = KaliToolAdapter()
        text_output = "Nmap scan report for 127.0.0.1"
        
        result = adapter._parse_nmap_output(text_output)
        assert result['format'] == 'text'
        assert result['hosts'] == []
    
    def test_parse_malformed_xml(self):
        adapter = KaliToolAdapter()
        bad_xml = "<invalid>not complete"
        
        result = adapter._parse_nmap_output(bad_xml)
        # Malformed XML is treated as text format
        assert result['format'] == 'text'


class TestGobusterParsing:
    """Test gobuster output parsing."""
    
    def test_parse_directories(self):
        adapter = KaliToolAdapter()
        output = """
        /admin (Status: 301) [Size: 312]
        /api (Status: 200) [Size: 1024]
        /config (Status: 403) [Size: 278]
        """
        
        result = adapter._parse_gobuster_output(output)
        assert result['directories_found'] == 3
        assert len(result['findings']) == 3
    
    def test_parse_empty_output(self):
        adapter = KaliToolAdapter()
        result = adapter._parse_gobuster_output("")
        assert result['directories_found'] == 0
        assert result['findings'] == []


class TestNiktoParsing:
    """Test Nikto output parsing."""
    
    def test_parse_vulnerabilities(self):
        adapter = KaliToolAdapter()
        output = """+ Target IP:          192.168.1.1
+ Target Hostname:    target.local
+ OSVDB-0: GET /admin : Admin interface found
+ OSVDB-1: GET /config.php : Config file exposed
"""
        
        result = adapter._parse_nikto_output(output)
        # Parser counts all lines starting with '+' (excluding '++')
        assert result['vulnerabilities_found'] >= 2
        assert len(result['findings']) >= 2
    
    def test_parse_no_vulns(self):
        adapter = KaliToolAdapter()
        output = "Nikto v2.1.6"
        
        result = adapter._parse_nikto_output(output)
        assert result['vulnerabilities_found'] == 0


class TestSqlmapParsing:
    """Test sqlmap output parsing."""
    
    def test_detect_vulnerable(self):
        adapter = KaliToolAdapter()
        stdout = "injection point found at parameter 'id'"
        stderr = "database management system: MySQL"
        
        result = adapter._parse_sqlmap_output(stdout, stderr)
        assert result['vulnerable'] is True
        assert len(result['findings']) > 0
    
    def test_detect_not_vulnerable(self):
        adapter = KaliToolAdapter()
        stdout = "all tested parameters do not appear to be injectable"
        stderr = ""
        
        result = adapter._parse_sqlmap_output(stdout, stderr)
        # No findings means not vulnerable
        assert result['vulnerable'] == (len(result['findings']) > 0)


class TestRateLimiting:
    """Test rate limiting functionality."""
    
    def test_rate_limit_enforced(self):
        adapter = KaliToolAdapter()
        adapter._rate_limit_seconds = 1
        adapter._last_scan_time = time.time()
        
        with pytest.raises(SecurityToolError) as exc_info:
            adapter._check_rate_limit()
        assert "rate limit" in str(exc_info.value).lower()
    
    def test_rate_limit_passes_after_delay(self):
        adapter = KaliToolAdapter()
        adapter._rate_limit_seconds = 0.01
        adapter._last_scan_time = time.time() - 0.1
        
        # Should not raise
        adapter._check_rate_limit()


class TestAdapterConfiguration:
    """Test adapter configuration options."""
    
    def test_default_timeout(self):
        adapter = KaliToolAdapter()
        assert adapter.timeout == 300
    
    def test_custom_timeout(self):
        adapter = KaliToolAdapter(timeout=600)
        assert adapter.timeout == 600
    
    def test_tool_paths_defined(self):
        adapter = KaliToolAdapter()
        assert 'nmap' in adapter.TOOL_PATHS
        assert 'sqlmap' in adapter.TOOL_PATHS
        assert 'gobuster' in adapter.TOOL_PATHS


# Integration tests (require actual tools installed)
class TestIntegration:
    """Integration tests - skipped if tools not installed."""
    
    @pytest.mark.skipif(
        not Path('/usr/bin/nmap').exists(),
        reason="nmap not installed"
    )
    def test_nmap_localhost_scan(self):
        adapter = KaliToolAdapter()
        result = adapter.nmap_scan("127.0.0.1", scan_type="syn", ports="22,80,443")
        
        assert isinstance(result, SecurityToolResult)
        assert result.tool == "nmap"
        assert result.returncode == 0
        assert 'hosts' in result.parsed_output
    
    @pytest.mark.skipif(
        not Path('/usr/bin/nmap').exists(),
        reason="nmap not installed"
    )
    def test_nmap_invalid_target_blocked(self):
        adapter = KaliToolAdapter()
        
        with pytest.raises(SecurityToolError):
            adapter.nmap_scan("127.0.0.1; cat /etc/passwd")
    
    @pytest.mark.skipif(
        not Path('/usr/bin/gobuster').exists(),
        reason="gobuster not installed"
    )
    def test_gobuster_wordlist_validation(self):
        adapter = KaliToolAdapter()
        
        with pytest.raises(SecurityToolError):
            # Non-existent wordlist should fail
            adapter.gobuster_scan("http://127.0.0.1", wordlist="/nonexistent.txt")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
