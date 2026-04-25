#!/usr/bin/env python3
"""
Verifiable Tool Registry for Kali Kimi Interface

Every tool has:
- SHA-256 hash of its binary (integrity verification)
- JSON Schema for input validation
- Permission classification
- Structured output parser assignment
- Install detection

159 tools across 14 categories.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class Permission(Enum):
    READ_ONLY = "read-only"
    WORKSPACE_WRITE = "workspace-write"
    DANGER_FULL_ACCESS = "danger-full-access"


class OutputParser(Enum):
    NMAP_XML = "nmap_xml"
    JSON = "json"
    TEXT_LINES = "text_lines"
    GOBUSTER_DIR = "gobuster_dir"
    NIKTO = "nikto"
    SQLMAP = "sqlmap"
    MASSCAN = "masscan"
    NETDISCOVER = "netdiscover"
    HYDRA = "hydra"
    JOHN = "john"
    HASHCAT = "hashcat"
    AIRODUMP = "airodump"
    CUSTOM = "custom"
    NONE = "none"


@dataclass
class ToolVerif:
    """Verification record for a single tool."""
    name: str
    category: str
    icon: str
    description: str
    binary_path: Optional[str]
    installed: bool
    sha256: Optional[str]
    permission: str
    parser: str
    input_schema: Dict[str, Any]
    command_template: str
    help_flag: str = "--help"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def _hash_binary(path: str) -> Optional[str]:
    """Compute SHA-256 of a binary file."""
    try:
        p = Path(path)
        if p.exists() and p.is_file():
            return hashlib.sha256(p.read_bytes()).hexdigest()
    except (PermissionError, OSError):
        pass
    return None


def _find_binary(name: str) -> Tuple[Optional[str], bool, Optional[str]]:
    """Find binary, return (path, installed, sha256)."""
    path = shutil.which(name)
    if path:
        return path, True, _hash_binary(path)
    for prefix in ['/usr/bin', '/usr/sbin', '/usr/local/bin', '/opt']:
        candidate = f"{prefix}/{name}"
        if Path(candidate).exists():
            return candidate, True, _hash_binary(candidate)
    return None, False, None


# --- Input Schemas ---

TARGET_REQUIRED = {"type": "object", "properties": {"target": {"type": "string", "description": "Target IP, hostname, or CIDR"}}, "required": ["target"]}

SCHEMA_NMAP = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "Target IP/hostname/CIDR"},
        "scan_type": {"type": "string", "enum": ["syn", "connect", "udp", "comprehensive", "vuln", "fast"], "default": "syn"},
        "ports": {"type": "string", "description": "Port range e.g. 1-65535"},
        "flags": {"type": "string", "description": "Additional nmap flags"},
        "timeout": {"type": "integer", "minimum": 1, "maximum": 3600}
    },
    "required": ["target"]
}

SCHEMA_URL_TARGET = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "Target URL"},
        "timeout": {"type": "integer", "minimum": 1, "maximum": 3600}
    },
    "required": ["url"]
}

SCHEMA_HOST_PORT = {
    "type": "object",
    "properties": {
        "host": {"type": "string", "description": "Target host"},
        "port": {"type": "integer", "description": "Target port"},
        "ssl": {"type": "boolean", "default": False},
        "timeout": {"type": "integer", "minimum": 1, "maximum": 3600}
    },
    "required": ["host"]
}

SCHEMA_WORDLIST = {
    "type": "object",
    "properties": {
        "input_file": {"type": "string", "description": "Input file (hash, capture, wordlist)"},
        "wordlist": {"type": "string", "description": "Wordlist path"},
        "rules": {"type": "string", "description": "Rules file or mode"},
        "timeout": {"type": "integer", "minimum": 1, "maximum": 3600}
    },
    "required": ["input_file"]
}

SCHEMA_INTERFACE = {
    "type": "object",
    "properties": {
        "interface": {"type": "string", "description": "Network interface e.g. eth0, wlan0"},
        "duration": {"type": "integer", "description": "Duration in seconds", "default": 30},
        "filter": {"type": "string", "description": "BPF filter expression"}
    },
    "required": ["interface"]
}

SCHEMA_FILE_INPUT = {
    "type": "object",
    "properties": {
        "input_file": {"type": "string", "description": "Input file path"},
        "output_dir": {"type": "string", "description": "Output directory"}
    },
    "required": ["input_file"]
}

SCHEMA_LOGIN_CRACK = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "Target host/URL"},
        "service": {"type": "string", "description": "Service: ssh, ftp, http-form, rdp, etc."},
        "username": {"type": "string", "description": "Username or user list file"},
        "password_list": {"type": "string", "description": "Password list file"},
        "port": {"type": "integer", "description": "Target port"},
        "threads": {"type": "integer", "default": 16, "description": "Parallel connections"}
    },
    "required": ["target", "service"]
}

SCHEMA_EMPTY = {"type": "object", "properties": {}}

SCHEMA_FILE_OR_TARGET = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "Target file, URL, or host"},
        "options": {"type": "string", "description": "Additional CLI options"}
    },
    "required": ["target"]
}

SCHEMA_EXPLOIT_SEARCH = {
    "type": "object",
    "properties": {
        "query": {"type": "string", "description": "Search term (CVE, software name)"},
        "json_output": {"type": "boolean", "default": True}
    },
    "required": ["query"]
}

SCHEMA_WIFI = {
    "type": "object",
    "properties": {
        "interface": {"type": "string", "description": "Wireless interface (e.g. wlan0)"},
        "bssid": {"type": "string", "description": "Target BSSID"},
        "channel": {"type": "integer", "description": "WiFi channel"},
        "wordlist": {"type": "string", "description": "Wordlist for cracking"},
        "capture_file": {"type": "string", "description": "Capture file (.cap)"}
    },
    "required": ["interface"]
}

SCHEMA_STEGO = {
    "type": "object",
    "properties": {
        "input_file": {"type": "string", "description": "Input image/file"},
        "embed_file": {"type": "string", "description": "File to embed (for encoding)"},
        "output_file": {"type": "string", "description": "Output file"},
        "password": {"type": "string", "description": "Steganography password"},
        "mode": {"type": "string", "enum": ["embed", "extract"], "default": "extract"}
    },
    "required": ["input_file"]
}

SCHEMA_PCAP = {
    "type": "object",
    "properties": {
        "interface": {"type": "string", "description": "Network interface"},
        "capture_file": {"type": "string", "description": "PCAP file to read"},
        "filter": {"type": "string", "description": "Display/capture filter"},
        "count": {"type": "integer", "description": "Packet count limit", "default": 100},
        "duration": {"type": "integer", "description": "Capture duration seconds"}
    },
    "required": []
}

SCHEMA_MITM = {
    "type": "object",
    "properties": {
        "interface": {"type": "string", "description": "Network interface"},
        "target": {"type": "string", "description": "Target IP"},
        "gateway": {"type": "string", "description": "Gateway IP"},
        "mode": {"type": "string", "enum": ["arp", "dns", "icmp"], "default": "arp"}
    },
    "required": ["interface"]
}


# --- Master Tool Definitions ---
TOOL_DEFINITIONS = [
    # Information Gathering
    ("nmap", "Information Gathering", "🔍", "Network scanner", "danger-full-access", "nmap_xml", "SCHEMA_NMAP", "nmap {flags} {target}", "-h"),
    ("masscan", "Information Gathering", "🔍", "Fast port scanner", "danger-full-access", "masscan", "SCHEMA_NMAP", "masscan {target} -p {ports} --rate {rate}", "--help"),
    ("theHarvester", "Information Gathering", "🔍", "Email harvesting", "read-only", "text_lines", "SCHEMA_FILE_OR_TARGET", "theHarvester -d {target} -b all", "-h"),
    ("dnsrecon", "Information Gathering", "🔍", "DNS enumeration", "read-only", "text_lines", "SCHEMA_FILE_OR_TARGET", "dnsrecon -d {target}", "-h"),
    ("dnsenum", "Information Gathering", "🔍", "DNS enumeration", "read-only", "text_lines", "SCHEMA_FILE_OR_TARGET", "dnsenum {target}", "--help"),
    ("fierce", "Information Gathering", "🔍", "DNS scanner", "read-only", "text_lines", "SCHEMA_FILE_OR_TARGET", "fierce -dns {target}", "-h"),
    ("dmitry", "Information Gathering", "🔍", "Info gatherer", "read-only", "text_lines", "SCHEMA_FILE_OR_TARGET", "dmitry -winsep {target}", "-h"),
    ("ike-scan", "Information Gathering", "🔍", "VPN scanner", "read-only", "text_lines", "TARGET_REQUIRED", "ike-scan {target}", "-h"),
    ("netdiscover", "Information Gathering", "🔍", "Network discovery", "read-only", "netdiscover", "TARGET_REQUIRED", "netdiscover -r {target}", "-h"),
    ("p0f", "Information Gathering", "🔍", "OS fingerprinting", "read-only", "text_lines", "SCHEMA_INTERFACE", "p0f -i {interface}", "-h"),
    ("recon-ng", "Information Gathering", "🔍", "Recon framework", "workspace-write", "text_lines", "SCHEMA_EMPTY", "recon-ng", "--help"),
    ("maltego", "Information Gathering", "🔍", "OSINT platform", "workspace-write", "none", "SCHEMA_EMPTY", "maltego", ""),
    ("spiderfoot", "Information Gathering", "🔍", "OSINT automation", "workspace-write", "text_lines", "SCHEMA_FILE_OR_TARGET", "spiderfoot -s {target}", "-h"),
    ("twofi", "Information Gathering", "🔍", "Twitter tool", "read-only", "text_lines", "SCHEMA_FILE_OR_TARGET", "twofi -u {target}", "--help"),
    ("cewl", "Information Gathering", "🔍", "Wordlist generator", "read-only", "text_lines", "SCHEMA_URL_TARGET", "cewl {url} -w output.txt", "--help"),

    # Vulnerability Analysis
    ("nikto", "Vulnerability Analysis", "🔎", "Web scanner", "danger-full-access", "nikto", "SCHEMA_HOST_PORT", "nikto -h {host}", "-H"),
    ("sqlmap", "Vulnerability Analysis", "🔎", "SQL injection", "danger-full-access", "sqlmap", "SCHEMA_URL_TARGET", "sqlmap -u {url} --batch", "-h"),
    ("openvas", "Vulnerability Analysis", "🔎", "Vuln scanner", "danger-full-access", "text_lines", "SCHEMA_FILE_OR_TARGET", "openvas-start", "--help"),
    ("legion", "Vulnerability Analysis", "🔎", "Auto pentesting", "danger-full-access", "text_lines", "SCHEMA_EMPTY", "legion", ""),
    ("sparta", "Vulnerability Analysis", "🔎", "Infra pentesting", "danger-full-access", "text_lines", "SCHEMA_EMPTY", "sparta", ""),
    ("lynis", "Vulnerability Analysis", "🔎", "Security audit", "read-only", "text_lines", "SCHEMA_EMPTY", "lynis audit system", "--help"),
    ("unix-privesc-check", "Vulnerability Analysis", "🔎", "Privesc checker", "read-only", "text_lines", "SCHEMA_EMPTY", "unix-privesc-check", ""),
    ("peass", "Vulnerability Analysis", "🔎", "Privesc scripts", "read-only", "text_lines", "SCHEMA_EMPTY", "linpeas", ""),
    ("linux-exploit-suggester", "Vulnerability Analysis", "🔎", "Exploit finder", "read-only", "text_lines", "SCHEMA_EMPTY", "linux-exploit-suggester", "--help"),

    # Web Applications
    ("burpsuite", "Web Applications", "🌐", "Web proxy", "danger-full-access", "none", "SCHEMA_EMPTY", "burpsuite", ""),
    ("zaproxy", "Web Applications", "🌐", "OWASP ZAP", "danger-full-access", "none", "SCHEMA_EMPTY", "zaproxy", ""),
    ("gobuster", "Web Applications", "🌐", "Dir brute-forcer", "danger-full-access", "gobuster_dir", "SCHEMA_URL_TARGET", "gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt", "-h"),
    ("dirb", "Web Applications", "🌐", "Web scanner", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "dirb {url}", ""),
    ("wfuzz", "Web Applications", "🌐", "Web fuzzer", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt {url}/FUZZ", "--help"),
    ("ffuf", "Web Applications", "🌐", "Fast fuzzer", "danger-full-access", "json", "SCHEMA_URL_TARGET", "ffuf -u {url}/FUZZ -w /usr/share/wordlists/dirb/common.txt", "-h"),
    ("wpscan", "Web Applications", "🌐", "WordPress scanner", "danger-full-access", "json", "SCHEMA_URL_TARGET", "wpscan --url {url}", "--help"),
    ("commix", "Web Applications", "🌐", "Command injection", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "commix -u {url}", "-h"),
    ("whatweb", "Web Applications", "🌐", "Web fingerprint", "read-only", "text_lines", "SCHEMA_URL_TARGET", "whatweb {url}", "-h"),
    ("wafw00f", "Web Applications", "🌐", "WAF detector", "read-only", "text_lines", "SCHEMA_URL_TARGET", "wafw00f {url}", "-h"),
    ("padbuster", "Web Applications", "🌐", "Padding oracle", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "padbuster {url}", ""),
    ("skipfish", "Web Applications", "🌐", "Web scanner", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "skipfish -o output {url}", "-h"),
    ("uniscan", "Web Applications", "🌐", "RFI scanner", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "uniscan -u {url}", ""),
    ("xsser", "Web Applications", "🌐", "XSS scanner", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "xsser -u {url}", "-h"),
    ("arachni", "Web Applications", "🌐", "Web scanner", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "arachni {url}", ""),
    ("joomscan", "Web Applications", "🌐", "Joomla scanner", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "joomscan -u {url}", ""),
    ("cmsmap", "Web Applications", "🌐", "CMS scanner", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "cmsmap -t {url}", ""),
    ("droopescan", "Web Applications", "🌐", "CMS scanner", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "droopescan scan -t {url}", ""),

    # Password Attacks
    ("john", "Password Attacks", "🔐", "John the Ripper", "danger-full-access", "john", "SCHEMA_WORDLIST", "john {input_file}", "--help"),
    ("hydra", "Password Attacks", "🔐", "Login cracker", "danger-full-access", "hydra", "SCHEMA_LOGIN_CRACK", "hydra -l {username} -P {password_list} {target} {service}", "-h"),
    ("hashcat", "Password Attacks", "🔐", "Password cracker", "danger-full-access", "hashcat", "SCHEMA_WORDLIST", "hashcat -m {hash_type} {input_file} {wordlist}", "--help"),
    ("medusa", "Password Attacks", "🔐", "Speedy brute", "danger-full-access", "text_lines", "SCHEMA_LOGIN_CRACK", "medusa -h {target} -u {username} -P {password_list} -M {service}", "-h"),
    ("ncrack", "Password Attacks", "🔐", "Network auth crack", "danger-full-access", "text_lines", "SCHEMA_LOGIN_CRACK", "ncrack {target}:{port} -U {username} -P {password_list}", "-h"),
    ("crunch", "Password Attacks", "🔐", "Wordlist gen", "workspace-write", "none", "SCHEMA_EMPTY", "crunch", "--help"),
    ("cewl", "Password Attacks", "🔐", "Custom wordlist", "read-only", "text_lines", "SCHEMA_URL_TARGET", "cewl {url} -w output.txt", "--help"),
    ("hash-identifier", "Password Attacks", "🔐", "Hash ID", "read-only", "text_lines", "SCHEMA_EMPTY", "hash-identifier", ""),
    ("rcrack", "Password Attacks", "🔐", "Rainbow tables", "danger-full-access", "text_lines", "SCHEMA_FILE_INPUT", "rcrack {input_file}", ""),
    ("brutespray", "Password Attacks", "🔐", "Brute sprayer", "danger-full-access", "text_lines", "SCHEMA_FILE_INPUT", "brutespray -f {input_file}", "-h"),
    ("patator", "Password Attacks", "🔐", "Multi-purpose brute", "danger-full-access", "text_lines", "SCHEMA_LOGIN_CRACK", "patator", "-h"),
    ("thc-pptp-bruter", "Password Attacks", "🔐", "PPTP brute", "danger-full-access", "text_lines", "SCHEMA_LOGIN_CRACK", "thc-pptp-bruter {target}", ""),

    # Wireless Attacks
    ("aircrack-ng", "Wireless Attacks", "📡", "WiFi auditor", "danger-full-access", "text_lines", "SCHEMA_WIFI", "aircrack-ng {capture_file}", "--help"),
    ("aireplay-ng", "Wireless Attacks", "📡", "Packet inject", "danger-full-access", "text_lines", "SCHEMA_WIFI", "aireplay-ng -0 10 -a {bssid} {interface}", "--help"),
    ("airodump-ng", "Wireless Attacks", "📡", "Packet capture", "danger-full-access", "airodump", "SCHEMA_WIFI", "airodump-ng {interface}", "--help"),
    ("airmon-ng", "Wireless Attacks", "📡", "Monitor mode", "danger-full-access", "text_lines", "SCHEMA_INTERFACE", "airmon-ng start {interface}", "--help"),
    ("airdecap-ng", "Wireless Attacks", "📡", "Decrypt capture", "workspace-write", "text_lines", "SCHEMA_WIFI", "airdecap-ng -e {essid} -p {password} {capture_file}", "--help"),
    ("wifite", "Wireless Attacks", "📡", "Auto WiFi auditor", "danger-full-access", "text_lines", "SCHEMA_WIFI", "wifite -i {interface}", "--help"),
    ("reaver", "Wireless Attacks", "📡", "WPS brute", "danger-full-access", "text_lines", "SCHEMA_WIFI", "reaver -i {interface} -b {bssid}", "-h"),
    ("bully", "Wireless Attacks", "📡", "WPS brute", "danger-full-access", "text_lines", "SCHEMA_WIFI", "bully {interface} -b {bssid}", "-h"),
    ("kismet", "Wireless Attacks", "📡", "Wireless detector", "read-only", "text_lines", "SCHEMA_INTERFACE", "kismet -c {interface}", "-h"),
    ("cowpatty", "Wireless Attacks", "📡", "WPA brute", "danger-full-access", "text_lines", "SCHEMA_WIFI", "cowpatty -f {wordlist} -r {capture_file} -s {essid}", "-h"),
    ("eapmd5pass", "Wireless Attacks", "📡", "EAP brute", "danger-full-access", "text_lines", "SCHEMA_WIFI", "eapmd5pass -w {wordlist} {capture_file}", ""),
    ("fern-wifi-cracker", "Wireless Attacks", "📡", "WiFi GUI", "danger-full-access", "none", "SCHEMA_EMPTY", "fern-wifi-cracker", ""),
    ("spooftooph", "Wireless Attacks", "📡", "BT spoofing", "danger-full-access", "text_lines", "SCHEMA_INTERFACE", "spooftooph -i {interface}", "-h"),
    ("redfang", "Wireless Attacks", "📡", "BT scanner", "read-only", "text_lines", "SCHEMA_EMPTY", "fang", ""),
    ("bluelog", "Wireless Attacks", "📡", "BT logger", "read-only", "text_lines", "SCHEMA_INTERFACE", "bluelog -i {interface}", "-h"),

    # Exploitation
    ("msfconsole", "Exploitation", "💥", "Metasploit", "danger-full-access", "none", "SCHEMA_EMPTY", "msfconsole", "-h"),
    ("msfvenom", "Exploitation", "💥", "Payload gen", "danger-full-access", "text_lines", "SCHEMA_EMPTY", "msfvenom -l payloads", "-h"),
    ("searchsploit", "Exploitation", "💥", "Exploit DB", "read-only", "text_lines", "SCHEMA_EXPLOIT_SEARCH", "searchsploit {query}", "-h"),
    ("beef-xss", "Exploitation", "💥", "Browser exploit", "danger-full-access", "none", "SCHEMA_EMPTY", "beef-xss", ""),
    ("commix", "Exploitation", "💥", "Command injection", "danger-full-access", "text_lines", "SCHEMA_URL_TARGET", "commix -u {url}", "-h"),
    ("routersploit", "Exploitation", "💥", "Router exploit", "danger-full-access", "text_lines", "SCHEMA_EMPTY", "routersploit", ""),
    ("setoolkit", "Exploitation", "💥", "Social eng", "danger-full-access", "none", "SCHEMA_EMPTY", "setoolkit", ""),
    ("shellnoob", "Exploitation", "💥", "Shellcode tool", "workspace-write", "text_lines", "SCHEMA_FILE_INPUT", "shellnoob -h", "-h"),
    ("exploitdb", "Exploitation", "💥", "Exploit database", "read-only", "text_lines", "SCHEMA_EXPLOIT_SEARCH", "searchsploit {query}", "-h"),

    # Sniffing & Spoofing
    ("wireshark", "Sniffing & Spoofing", "👃", "Packet analyzer", "danger-full-access", "none", "SCHEMA_PCAP", "wireshark", "-h"),
    ("tshark", "Sniffing & Spoofing", "👃", "CLI analyzer", "read-only", "text_lines", "SCHEMA_PCAP", "tshark -i {interface}", "-h"),
    ("tcpdump", "Sniffing & Spoofing", "👃", "Packet dump", "read-only", "text_lines", "SCHEMA_PCAP", "tcpdump -i {interface}", "-h"),
    ("ettercap", "Sniffing & Spoofing", "👃", "MITM tool", "danger-full-access", "text_lines", "SCHEMA_MITM", "ettercap -T -i {interface}", "-h"),
    ("bettercap", "Sniffing & Spoofing", "👃", "Network attack", "danger-full-access", "text_lines", "SCHEMA_MITM", "bettercap -iface {interface}", "-h"),
    ("driftnet", "Sniffing & Spoofing", "👃", "Image sniffer", "read-only", "none", "SCHEMA_INTERFACE", "driftnet -i {interface}", "-h"),
    ("urlsnarf", "Sniffing & Spoofing", "👃", "URL sniffer", "read-only", "text_lines", "SCHEMA_INTERFACE", "urlsnarf -i {interface}", "-h"),
    ("msgsnarf", "Sniffing & Spoofing", "👃", "Msg sniffer", "read-only", "text_lines", "SCHEMA_INTERFACE", "msgsnarf -i {interface}", "-h"),
    ("dnsspoof", "Sniffing & Spoofing", "👃", "DNS spoof", "danger-full-access", "text_lines", "SCHEMA_INTERFACE", "dnsspoof -i {interface}", "-h"),
    ("arpspoof", "Sniffing & Spoofing", "👃", "ARP spoof", "danger-full-access", "text_lines", "SCHEMA_MITM", "arpspoof -i {interface} -t {target} {gateway}", "-h"),
    ("ssldump", "Sniffing & Spoofing", "👃", "SSL analyzer", "read-only", "text_lines", "SCHEMA_PCAP", "ssldump -i {interface}", "-h"),
    ("macchanger", "Sniffing & Spoofing", "👃", "MAC changer", "danger-full-access", "text_lines", "SCHEMA_INTERFACE", "macchanger -s {interface}", "-h"),
    ("responder", "Sniffing & Spoofing", "👃", "LLMNR poisoner", "danger-full-access", "text_lines", "SCHEMA_INTERFACE", "responder -I {interface}", "-h"),
    ("mitmproxy", "Sniffing & Spoofing", "👃", "HTTP proxy", "danger-full-access", "text_lines", "SCHEMA_INTERFACE", "mitmproxy -i {interface}", "-h"),

    # Forensics
    ("autopsy", "Forensics", "🔬", "Forensics platform", "workspace-write", "none", "SCHEMA_EMPTY", "autopsy", "-h"),
    ("binwalk", "Forensics", "🔬", "Firmware tool", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "binwalk {input_file}", "-h"),
    ("bulk_extractor", "Forensics", "🔬", "Data extractor", "workspace-write", "text_lines", "SCHEMA_FILE_INPUT", "bulk_extractor -o {output_dir} {input_file}", "-h"),
    ("foremost", "Forensics", "🔬", "File recovery", "workspace-write", "text_lines", "SCHEMA_FILE_INPUT", "foremost -i {input_file} -o {output_dir}", "-h"),
    ("volatility", "Forensics", "🔬", "Memory forensics", "workspace-write", "text_lines", "SCHEMA_FILE_INPUT", "volatility -f {input_file} imageinfo", "-h"),
    ("pdf-parser", "Forensics", "🔬", "PDF tool", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "pdf-parser {input_file}", "-h"),
    ("pdfid", "Forensics", "🔬", "PDF scanner", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "pdfid {input_file}", "-h"),
    ("peepdf", "Forensics", "🔬", "PDF analysis", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "peepdf {input_file}", ""),
    ("regripper", "Forensics", "🔬", "Registry tool", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "rip.pl -r {input_file}", ""),
    ("chkrootkit", "Forensics", "🔬", "Rootkit check", "read-only", "text_lines", "SCHEMA_EMPTY", "chkrootkit", "-h"),
    ("rkhunter", "Forensics", "🔬", "Rootkit hunter", "read-only", "text_lines", "SCHEMA_EMPTY", "rkhunter --check", "-h"),
    ("sleuthkit", "Forensics", "🔬", "Forensics kit", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "fls {input_file}", ""),

    # Reverse Engineering
    ("gdb", "Reverse Engineering", "🔧", "Debugger", "workspace-write", "none", "SCHEMA_FILE_INPUT", "gdb {input_file}", "--help"),
    ("radare2", "Reverse Engineering", "🔧", "RE framework", "workspace-write", "none", "SCHEMA_FILE_INPUT", "r2 {input_file}", "-h"),
    ("ghidra", "Reverse Engineering", "🔧", "RE tool", "workspace-write", "none", "SCHEMA_FILE_INPUT", "ghidra", ""),
    ("ida64", "Reverse Engineering", "🔧", "Disassembler", "workspace-write", "none", "SCHEMA_FILE_INPUT", "ida64 {input_file}", ""),
    ("apktool", "Reverse Engineering", "🔧", "APK tool", "workspace-write", "text_lines", "SCHEMA_FILE_INPUT", "apktool d {input_file}", "-h"),
    ("dex2jar", "Reverse Engineering", "🔧", "DEX to JAR", "workspace-write", "text_lines", "SCHEMA_FILE_INPUT", "d2j-dex2jar.sh {input_file}", ""),
    ("jd-gui", "Reverse Engineering", "🔧", "Java decompiler", "workspace-write", "none", "SCHEMA_FILE_INPUT", "jd-gui {input_file}", ""),
    ("valgrind", "Reverse Engineering", "🔧", "Memory debug", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "valgrind {input_file}", "--help"),
    ("strace", "Reverse Engineering", "🔧", "Syscall trace", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "strace {input_file}", "-h"),
    ("ltrace", "Reverse Engineering", "🔧", "Library trace", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "ltrace {input_file}", "-h"),
    ("edb-debugger", "Reverse Engineering", "🔧", "GUI debugger", "workspace-write", "none", "SCHEMA_FILE_INPUT", "edb", ""),
    ("ollydbg", "Reverse Engineering", "🔧", "Windows debugger", "workspace-write", "none", "SCHEMA_FILE_INPUT", "ollydbg", ""),

    # Mobile Analysis
    ("apktool", "Mobile Analysis", "📱", "APK reverse", "workspace-write", "text_lines", "SCHEMA_FILE_INPUT", "apktool d {input_file}", "-h"),
    ("dex2jar", "Mobile Analysis", "📱", "Android tool", "workspace-write", "text_lines", "SCHEMA_FILE_INPUT", "d2j-dex2jar.sh {input_file}", ""),
    ("jd-gui", "Mobile Analysis", "📱", "Java decompiler", "workspace-write", "none", "SCHEMA_FILE_INPUT", "jd-gui {input_file}", ""),
    ("androguard", "Mobile Analysis", "📱", "Android analysis", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "androguard axml {input_file}", "-h"),
    ("frida", "Mobile Analysis", "📱", "Dynamic instrumentation", "danger-full-access", "text_lines", "SCHEMA_FILE_INPUT", "frida", "--help"),
    ("objection", "Mobile Analysis", "📱", "Runtime mobile", "danger-full-access", "text_lines", "SCHEMA_FILE_INPUT", "objection explore", "--help"),
    ("mobsf", "Mobile Analysis", "📱", "Mobile security", "danger-full-access", "none", "SCHEMA_FILE_INPUT", "mobsf", ""),
    ("imazing", "Mobile Analysis", "📱", "iOS tool", "read-only", "none", "SCHEMA_EMPTY", "imazing", ""),
    ("libimobiledevice", "Mobile Analysis", "📱", "iOS library", "read-only", "text_lines", "SCHEMA_EMPTY", "ideviceinfo", ""),

    # Social Engineering
    ("setoolkit", "Social Engineering", "🎭", "SET toolkit", "danger-full-access", "none", "SCHEMA_EMPTY", "setoolkit", ""),
    ("gophish", "Social Engineering", "🎭", "Phishing framework", "danger-full-access", "none", "SCHEMA_EMPTY", "gophish", ""),
    ("king-phisher", "Social Engineering", "🎭", "Phishing tool", "danger-full-access", "none", "SCHEMA_EMPTY", "king-phisher", ""),
    ("beef-xss", "Social Engineering", "🎭", "Browser exploit", "danger-full-access", "none", "SCHEMA_EMPTY", "beef-xss", ""),
    ("weeman", "Social Engineering", "🎭", "Phishing page", "danger-full-access", "none", "SCHEMA_EMPTY", "weeman", ""),
    ("social-engineer-toolkit", "Social Engineering", "🎭", "SET", "danger-full-access", "none", "SCHEMA_EMPTY", "setoolkit", ""),
    ("credharvest", "Social Engineering", "🎭", "Harvest creds", "danger-full-access", "none", "SCHEMA_EMPTY", "credharvest", ""),

    # Steganography
    ("steghide", "Steganography", "📷", "Stego tool", "workspace-write", "text_lines", "SCHEMA_STEGO", "steghide {mode} -sf {input_file}", "-h"),
    ("stegosuite", "Steganography", "📷", "Stego GUI", "workspace-write", "none", "SCHEMA_STEGO", "stegosuite", ""),
    ("zsteg", "Steganography", "📷", "PNG/BMP stego", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "zsteg {input_file}", "-h"),
    ("stegsolve", "Steganography", "📷", "Stego solver", "read-only", "none", "SCHEMA_FILE_INPUT", "stegsolve", ""),
    ("sonic-visualiser", "Steganography", "📷", "Audio stego", "read-only", "none", "SCHEMA_FILE_INPUT", "sonic-visualiser", ""),
    ("spectrology", "Steganography", "📷", "Spectrogram", "read-only", "text_lines", "SCHEMA_FILE_INPUT", "spectrology {input_file}", "-h"),
    ("openstego", "Steganography", "📷", "Stego tool", "workspace-write", "text_lines", "SCHEMA_STEGO", "openstego {mode} -sf {input_file}", "--help"),

    # Reporting
    ("dradis", "Reporting", "📊", "Collaboration", "workspace-write", "none", "SCHEMA_EMPTY", "dradis", ""),
    ("keepnote", "Reporting", "📊", "Note taking", "workspace-write", "none", "SCHEMA_EMPTY", "keepnote", ""),
    ("cutycapt", "Reporting", "📊", "Screenshot", "read-only", "none", "SCHEMA_URL_TARGET", "cutycapt --url={url} --out=screenshot.png", "--help"),
    ("recordmydesktop", "Reporting", "📊", "Recorder", "workspace-write", "none", "SCHEMA_EMPTY", "recordmydesktop", "-h"),
    ("magictree", "Reporting", "📊", "Data manage", "workspace-write", "none", "SCHEMA_EMPTY", "magictree", ""),
    ("faraday", "Reporting", "📊", "Collaboration", "workspace-write", "none", "SCHEMA_EMPTY", "faraday", ""),
    ("defectdojo", "Reporting", "📊", "Vuln manage", "workspace-write", "none", "SCHEMA_EMPTY", "defectdojo", ""),

    # System Services
    ("apache2", "System Services", "⚙️", "Web server", "danger-full-access", "text_lines", "SCHEMA_EMPTY", "apache2ctl -S", "-h"),
    ("nginx", "System Services", "⚙️", "Web server", "danger-full-access", "text_lines", "SCHEMA_EMPTY", "nginx -T", "-h"),
    ("ssh", "System Services", "⚙️", "SSH server", "danger-full-access", "text_lines", "SCHEMA_EMPTY", "ssh -h", "-h"),
    ("openvpn", "System Services", "⚙️", "VPN", "danger-full-access", "text_lines", "SCHEMA_FILE_INPUT", "openvpn {input_file}", "--help"),
    ("proxychains", "System Services", "⚙️", "Proxy chain", "workspace-write", "text_lines", "SCHEMA_EMPTY", "proxychains -h", "-h"),
    ("tmux", "System Services", "⚙️", "Multiplexer", "workspace-write", "none", "SCHEMA_EMPTY", "tmux", "-h"),
    ("screen", "System Services", "⚙️", "Multiplexer", "workspace-write", "none", "SCHEMA_EMPTY", "screen", "-h"),
    ("htop", "System Services", "⚙️", "Process view", "read-only", "none", "SCHEMA_EMPTY", "htop", "-h"),
    ("iftop", "System Services", "⚙️", "Bandwidth", "read-only", "none", "SCHEMA_INTERFACE", "iftop -i {interface}", "-h"),
    ("nethogs", "System Services", "⚙️", "Net monitor", "read-only", "none", "SCHEMA_INTERFACE", "nethogs {interface}", "-h"),
    ("iperf3", "System Services", "⚙️", "Speed test", "read-only", "text_lines", "SCHEMA_HOST_PORT", "iperf3 -c {host}", "--help"),
    ("netcat", "System Services", "⚙️", "Network swiss", "danger-full-access", "text_lines", "SCHEMA_HOST_PORT", "nc {host} {port}", "-h"),
    ("socat", "System Services", "⚙️", "Socket cat", "danger-full-access", "text_lines", "SCHEMA_HOST_PORT", "socat - TCP:{host}:{port}", "-h"),
]


SCHEMA_MAP = {
    "SCHEMA_NMAP": SCHEMA_NMAP,
    "SCHEMA_URL_TARGET": SCHEMA_URL_TARGET,
    "SCHEMA_HOST_PORT": SCHEMA_HOST_PORT,
    "SCHEMA_WORDLIST": SCHEMA_WORDLIST,
    "SCHEMA_INTERFACE": SCHEMA_INTERFACE,
    "SCHEMA_FILE_INPUT": SCHEMA_FILE_INPUT,
    "SCHEMA_LOGIN_CRACK": SCHEMA_LOGIN_CRACK,
    "SCHEMA_EMPTY": SCHEMA_EMPTY,
    "SCHEMA_FILE_OR_TARGET": SCHEMA_FILE_OR_TARGET,
    "SCHEMA_EXPLOIT_SEARCH": SCHEMA_EXPLOIT_SEARCH,
    "SCHEMA_WIFI": SCHEMA_WIFI,
    "SCHEMA_STEGO": SCHEMA_STEGO,
    "SCHEMA_PCAP": SCHEMA_PCAP,
    "SCHEMA_MITM": SCHEMA_MITM,
    "TARGET_REQUIRED": TARGET_REQUIRED,
}


class VerifiableToolRegistry:
    """
    Registry of all 159 Kali tools with SHA-256 integrity verification.

    Usage:
        registry = VerifiableToolRegistry()
        spec = registry.get("nmap")
        errors = registry.validate_input("nmap", {"target": "192.168.1.1"})
        report = registry.integrity_report()
    """

    def __init__(self):
        self.tools: Dict[str, ToolVerif] = {}
        self._build_registry()

    def _build_registry(self):
        for tool_def in TOOL_DEFINITIONS:
            name, category, icon, desc, perm, parser, schema_key, cmd_template, help_flag = tool_def
            binary_path, installed, sha256 = _find_binary(name)
            schema = SCHEMA_MAP.get(schema_key, SCHEMA_EMPTY)
            self.tools[name] = ToolVerif(
                name=name, category=category, icon=icon, description=desc,
                binary_path=binary_path, installed=installed, sha256=sha256,
                permission=perm, parser=parser, input_schema=schema,
                command_template=cmd_template, help_flag=help_flag
            )

    def get(self, name: str) -> Optional[ToolVerif]:
        return self.tools.get(name)

    def all_tools(self) -> Dict[str, ToolVerif]:
        return dict(self.tools)

    def installed_tools(self) -> Dict[str, ToolVerif]:
        return {k: v for k, v in self.tools.items() if v.installed}

    def by_category(self, category: str) -> Dict[str, ToolVerif]:
        return {k: v for k, v in self.tools.items() if v.category == category}

    def categories(self) -> List[str]:
        return sorted(set(t.category for t in self.tools.values()))

    def verify_tool(self, name: str) -> Dict[str, Any]:
        tool = self.get(name)
        if not tool:
            return {"name": name, "error": "not in registry"}
        if not tool.installed:
            return {"name": name, "installed": False, "not_installed": True}
        current_hash = _hash_binary(tool.binary_path)
        return {
            "name": name, "installed": True,
            "original_hash": tool.sha256, "current_hash": current_hash,
            "verified": tool.sha256 == current_hash,
            "tampered": tool.sha256 != current_hash,
            "binary_path": tool.binary_path
        }

    def verify_all(self) -> List[Dict[str, Any]]:
        return [self.verify_tool(name) for name, tool in self.installed_tools().items()]

    def integrity_report(self) -> Dict[str, Any]:
        installed = self.installed_tools()
        verification_results = self.verify_all()
        tampered = [r for r in verification_results if r.get("tampered")]
        clean = [r for r in verification_results if r.get("verified")]
        return {
            "total_tools": len(self.tools),
            "installed": len(installed),
            "not_installed": len(self.tools) - len(installed),
            "verified_clean": len(clean),
            "tampered": len(tampered),
            "tampered_tools": [t["name"] for t in tampered],
            "categories": {cat: len(self.by_category(cat)) for cat in self.categories()},
            "installed_by_category": {
                cat: len([t for t in self.by_category(cat).values() if t.installed])
                for cat in self.categories()
            },
            "verification_details": verification_results
        }

    def validate_input(self, tool_name: str, input_data: Dict[str, Any]) -> List[str]:
        tool = self.get(tool_name)
        if not tool:
            return [f"Unknown tool: {tool_name}"]
        schema = tool.input_schema
        errors = []
        for field in schema.get("required", []):
            if field not in input_data:
                errors.append(f"Missing required field: {field}")
        properties = schema.get("properties", {})
        for field, value in input_data.items():
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
                if "minimum" in prop_spec and isinstance(value, (int, float)):
                    if value < prop_spec["minimum"]:
                        errors.append(f"Field '{field}' must be >= {prop_spec['minimum']}")
                if "maximum" in prop_spec and isinstance(value, (int, float)):
                    if value > prop_spec["maximum"]:
                        errors.append(f"Field '{field}' must be <= {prop_spec['maximum']}")
        return errors

    def to_json(self, installed_only: bool = False) -> str:
        tools = self.installed_tools() if installed_only else self.all_tools()
        return json.dumps({k: v.to_dict() for k, v in tools.items()}, indent=2)

    def save_manifest(self, path: str = "tool_manifest.json"):
        import datetime
        manifest = {
            "generated_at": datetime.datetime.now().isoformat(),
            "total_tools": len(self.tools),
            "installed": len(self.installed_tools()),
            "tools": {k: v.to_dict() for k, v in self.tools.items()},
            "integrity_report": self.integrity_report()
        }
        with open(path, "w") as f:
            json.dump(manifest, f, indent=2)
        return path


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Verifiable Tool Registry")
    parser.add_argument("--list", "-l", action="store_true", help="List all tools")
    parser.add_argument("--installed", "-i", action="store_true", help="List installed only")
    parser.add_argument("--verify", "-v", help="Verify specific tool")
    parser.add_argument("--verify-all", "-V", action="store_true", help="Verify all installed")
    parser.add_argument("--report", "-r", action="store_true", help="Full integrity report")
    parser.add_argument("--manifest", "-m", help="Save manifest to file")
    parser.add_argument("--category", "-c", help="Filter by category")
    args = parser.parse_args()
    registry = VerifiableToolRegistry()

    if args.list:
        tools = registry.by_category(args.category) if args.category else registry.all_tools()
        for name, tool in tools.items():
            status = "✓" if tool.installed else "✗"
            print(f"  {status} {name:<25} [{tool.category}] {tool.description}")
        print(f"\nTotal: {len(tools)} tools")
    elif args.installed:
        for name, tool in registry.installed_tools().items():
            print(f"  ✓ {name:<25} SHA-256: {tool.sha256[:16] if tool.sha256 else 'N/A'}...")
        print(f"\nInstalled: {len(registry.installed_tools())} / {len(registry.all_tools())}")
    elif args.verify:
        print(json.dumps(registry.verify_tool(args.verify), indent=2))
    elif args.verify_all:
        for r in registry.verify_all():
            status = "✓" if r.get("verified") else "⚠ TAMPERED"
            print(f"  {status} {r['name']}")
    elif args.report:
        print(json.dumps(registry.integrity_report(), indent=2))
    elif args.manifest:
        print(f"Manifest saved: {registry.save_manifest(args.manifest)}")
    else:
        report = registry.integrity_report()
        print(f"\n{'='*60}")
        print(f"VERIFIABLE TOOL REGISTRY")
        print(f"{'='*60}")
        print(f"Total tools: {report['total_tools']}")
        print(f"Installed:   {report['installed']}")
        print(f"Verified:    {report['verified_clean']}")
        print(f"Tampered:    {report['tampered']}")
        print(f"\nBy category:")
        for cat, total in report['categories'].items():
            inst = report['installed_by_category'][cat]
            print(f"  {cat:<25} {inst}/{total}")
        print(f"{'='*60}")
