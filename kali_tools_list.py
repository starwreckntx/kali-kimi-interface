#!/usr/bin/env python3
"""
Kali Linux Tools - Complete Listing with Categories
A comprehensive catalog of all CLI tools organized by category
"""

import shutil
from typing import Dict, List, Tuple

# Comprehensive Kali Linux tools database
KALI_TOOLS = {
    'Information Gathering': {
        'icon': '🔍',
        'description': 'Reconnaissance and OSINT tools',
        'tools': [
            ('nmap', 'Network scanner'),
            ('masscan', 'Fast port scanner'),
            ('theHarvester', 'Email harvesting'),
            ('dnsrecon', 'DNS enumeration'),
            ('dnsenum', 'DNS enumeration'),
            ('fierce', 'DNS scanner'),
            ('dmitry', 'Info gatherer'),
            ('ike-scan', 'VPN scanner'),
            ('netdiscover', 'Network discovery'),
            ('p0f', 'OS fingerprinting'),
            ('recon-ng', 'Recon framework'),
            ('maltego', 'OSINT platform'),
            ('spiderfoot', 'OSINT automation'),
            ('twofi', 'Twitter tool'),
            ('cewl', 'Wordlist generator'),
        ]
    },
    'Vulnerability Analysis': {
        'icon': '🔎',
        'description': 'Vulnerability scanning',
        'tools': [
            ('nikto', 'Web scanner'),
            ('sqlmap', 'SQL injection'),
            ('openvas', 'Vuln scanner'),
            ('legion', 'Auto pentesting'),
            ('sparta', 'Infra pentesting'),
            ('lynis', 'Security audit'),
            ('unix-privesc-check', 'Privesc checker'),
            ('peass', 'Privesc scripts'),
            ('linux-exploit-suggester', 'Exploit finder'),
        ]
    },
    'Web Applications': {
        'icon': '🌐',
        'description': 'Web app testing',
        'tools': [
            ('burpsuite', 'Web proxy'),
            ('zaproxy', 'OWASP ZAP'),
            ('gobuster', 'Dir brute-forcer'),
            ('dirb', 'Web scanner'),
            ('wfuzz', 'Web fuzzer'),
            ('ffuf', 'Fast fuzzer'),
            ('wpscan', 'WordPress scanner'),
            ('commix', 'Command injection'),
            ('whatweb', 'Web fingerprint'),
            ('wafw00f', 'WAF detector'),
            ('padbuster', 'Padding oracle'),
            ('skipfish', 'Web scanner'),
            ('uniscan', 'RFI scanner'),
            ('xsser', 'XSS scanner'),
            ('arachni', 'Web scanner'),
            ('joomscan', 'Joomla scanner'),
            ('cmsmap', 'CMS scanner'),
            ('droopescan', 'CMS scanner'),
        ]
    },
    'Password Attacks': {
        'icon': '🔐',
        'description': 'Password cracking',
        'tools': [
            ('john', 'John the Ripper'),
            ('hydra', 'Login cracker'),
            ('hashcat', 'Password cracker'),
            ('medusa', 'Speedy brute'),
            ('ncrack', 'Network auth crack'),
            ('crunch', 'Wordlist gen'),
            ('cewl', 'Custom wordlist'),
            ('hash-identifier', 'Hash ID'),
            ('rcrack', 'Rainbow tables'),
            ('brutespray', 'Brute sprayer'),
            ('patator', 'Multi-purpose brute'),
            ('thc-pptp-bruter', 'PPTP brute'),
        ]
    },
    'Wireless Attacks': {
        'icon': '📡',
        'description': 'WiFi and wireless',
        'tools': [
            ('aircrack-ng', 'WiFi auditor'),
            ('aireplay-ng', 'Packet inject'),
            ('airodump-ng', 'Packet capture'),
            ('airmon-ng', 'Monitor mode'),
            ('airdecap-ng', 'Decrypt capture'),
            ('wifite', 'Auto WiFi auditor'),
            ('reaver', 'WPS brute'),
            ('bully', 'WPS brute'),
            ('kismet', 'Wireless detector'),
            ('cowpatty', 'WPA brute'),
            ('eapmd5pass', 'EAP brute'),
            ('fern-wifi-cracker', 'WiFi GUI'),
            ('spooftooph', 'BT spoofing'),
            ('redfang', 'BT scanner'),
            ('bluelog', 'BT logger'),
        ]
    },
    'Exploitation': {
        'icon': '💥',
        'description': 'Exploit tools',
        'tools': [
            ('msfconsole', 'Metasploit'),
            ('msfvenom', 'Payload gen'),
            ('searchsploit', 'Exploit DB'),
            ('beef-xss', 'Browser exploit'),
            ('commix', 'Command injection'),
            ('routersploit', 'Router exploit'),
            ('setoolkit', 'Social eng'),
            ('shellnoob', 'Shellcode tool'),
            ('exploitdb', 'Exploit database'),
        ]
    },
    'Sniffing & Spoofing': {
        'icon': '👃',
        'description': 'Network MITM',
        'tools': [
            ('wireshark', 'Packet analyzer'),
            ('tshark', 'CLI analyzer'),
            ('tcpdump', 'Packet dump'),
            ('ettercap', 'MITM tool'),
            ('bettercap', 'Network attack'),
            ('driftnet', 'Image sniffer'),
            ('urlsnarf', 'URL sniffer'),
            ('msgsnarf', 'Msg sniffer'),
            ('dnsspoof', 'DNS spoof'),
            ('arpspoof', 'ARP spoof'),
            ('ssldump', 'SSL analyzer'),
            ('macchanger', 'MAC changer'),
            ('responder', 'LLMNR poisoner'),
            ('mitmproxy', 'HTTP proxy'),
        ]
    },
    'Forensics': {
        'icon': '🔬',
        'description': 'Digital forensics',
        'tools': [
            ('autopsy', 'Forensics platform'),
            ('binwalk', 'Firmware tool'),
            ('bulk_extractor', 'Data extractor'),
            ('foremost', 'File recovery'),
            ('volatility', 'Memory forensics'),
            ('pdf-parser', 'PDF tool'),
            ('pdfid', 'PDF scanner'),
            ('peepdf', 'PDF analysis'),
            ('regripper', 'Registry tool'),
            ('chkrootkit', 'Rootkit check'),
            ('rkhunter', 'Rootkit hunter'),
            ('sleuthkit', 'Forensics kit'),
        ]
    },
    'Reverse Engineering': {
        'icon': '🔧',
        'description': 'Binary analysis',
        'tools': [
            ('gdb', 'Debugger'),
            ('radare2', 'RE framework'),
            ('ghidra', 'RE tool'),
            ('ida64', 'Disassembler'),
            ('apktool', 'APK tool'),
            ('dex2jar', 'DEX to JAR'),
            ('jd-gui', 'Java decompiler'),
            ('valgrind', 'Memory debug'),
            ('strace', 'Syscall trace'),
            ('ltrace', 'Library trace'),
            ('edb-debugger', 'GUI debugger'),
            ('ollydbg', 'Windows debugger'),
        ]
    },
    'Mobile Analysis': {
        'icon': '📱',
        'description': 'Mobile pentesting',
        'tools': [
            ('apktool', 'APK reverse'),
            ('dex2jar', 'Android tool'),
            ('jd-gui', 'Java decompiler'),
            ('androguard', 'Android analysis'),
            ('frida', 'Dynamic instrumentation'),
            ('objection', 'Runtime mobile'),
            ('mobsf', 'Mobile security'),
            ('imazing', 'iOS tool'),
            ('libimobiledevice', 'iOS library'),
        ]
    },
    'Social Engineering': {
        'icon': '🎭',
        'description': 'Social eng tools',
        'tools': [
            ('setoolkit', 'SET toolkit'),
            ('gophish', 'Phishing framework'),
            ('king-phisher', 'Phishing tool'),
            ('beef-xss', 'Browser exploit'),
            ('weeman', 'Phishing page'),
            ('social-engineer-toolkit', 'SET'),
            ('credharvest', 'Harvest creds'),
        ]
    },
    'Steganography': {
        'icon': '📷',
        'description': 'Hide data',
        'tools': [
            ('steghide', 'Stego tool'),
            ('stegosuite', 'Stego GUI'),
            ('zsteg', 'PNG/BMP stego'),
            ('stegsolve', 'Stego solver'),
            ('sonic-visualiser', 'Audio stego'),
            ('spectrology', 'Spectrogram'),
            ('openstego', 'Stego tool'),
        ]
    },
    'Reporting': {
        'icon': '📊',
        'description': 'Documentation',
        'tools': [
            ('dradis', 'Collaboration'),
            ('keepnote', 'Note taking'),
            ('cutycapt', 'Screenshot'),
            ('recordmydesktop', 'Recorder'),
            ('magictree', 'Data manage'),
            ('faraday', 'Collaboration'),
            ('defectdojo', 'Vuln manage'),
        ]
    },
    'System Services': {
        'icon': '⚙️',
        'description': 'Services & utils',
        'tools': [
            ('apache2', 'Web server'),
            ('nginx', 'Web server'),
            ('ssh', 'SSH server'),
            ('openvpn', 'VPN'),
            ('proxychains', 'Proxy chain'),
            ('tmux', 'Multiplexer'),
            ('screen', 'Multiplexer'),
            ('htop', 'Process view'),
            ('iftop', 'Bandwidth'),
            ('nethogs', 'Net monitor'),
            ('iperf3', 'Speed test'),
            ('netcat', 'Network swiss'),
            ('socat', 'Socket cat'),
        ]
    },
}


def check_tool(tool_name: str) -> bool:
    """Check if tool is installed"""
    return shutil.which(tool_name) is not None


def print_tool_list():
    """Print comprehensive tool list"""
    print("\n" + "=" * 80)
    print(" " * 20 + "KALI LINUX CLI TOOLS - COMPLETE LISTING")
    print("=" * 80)
    
    total_tools = 0
    installed_tools = 0
    
    for category, data in KALI_TOOLS.items():
        icon = data.get('icon', '•')
        print(f"\n{icon} {category.upper()}")
        print("-" * 80)
        print(f"  {data['description']}")
        print()
        
        # Print tools in 3 columns
        tools = data['tools']
        col_width = 25
        
        for i in range(0, len(tools), 3):
            row_tools = tools[i:i+3]
            row = ""
            for tool_name, desc in row_tools:
                total_tools += 1
                if check_tool(tool_name):
                    installed_tools += 1
                    status = "✓"
                    tool_display = f"{tool_name:<18}"
                else:
                    status = " "
                    tool_display = f"{tool_name:<18}"
                
                col = f"{status} {tool_display}"
                row += col.ljust(col_width)
            print(f"  {row}")
    
    print("\n" + "=" * 80)
    print(f"Total Tools in Database: {total_tools}")
    print(f"Installed on System: {installed_tools}")
    print(f"Coverage: {installed_tools/total_tools*100:.1f}%")
    print("=" * 80)
    print("\n  ✓ = Installed    (blank) = Not installed")
    print("\n  To install missing tools:")
    print("    sudo apt update && sudo apt install -y <tool-name>")
    print()


def print_compact_menu():
    """Print compact start menu style"""
    print("\n" + "╔" + "═" * 78 + "╗")
    print("║" + " " * 25 + "KALI LINUX START MENU" + " " * 32 + "║")
    print("╠" + "═" * 78 + "╣")
    
    idx = 1
    for category, data in KALI_TOOLS.items():
        icon = data.get('icon', '•')
        installed = sum(1 for tool, _ in data['tools'] if check_tool(tool))
        total = len(data['tools'])
        status = f"[{installed}/{total}]"
        
        line = f"  {idx:2}. {icon} {category:<25} {status:>8}"
        print("║" + line.ljust(78) + "║")
        idx += 1
    
    print("╠" + "═" * 78 + "╣")
    print("║" + "  S. Search Tool  │  I. System Info  │  T. Terminal  │  Q. Quit".ljust(78) + "║")
    print("╚" + "═" * 78 + "╝")
    print()


def print_category_tools(category_name: str):
    """Print tools for a specific category"""
    if category_name not in KALI_TOOLS:
        print(f"Category '{category_name}' not found!")
        return
    
    data = KALI_TOOLS[category_name]
    icon = data.get('icon', '•')
    
    print("\n" + "=" * 80)
    print(f"{icon} {category_name.upper()}")
    print("=" * 80)
    print(f"{data['description']}\n")
    
    for idx, (tool_name, desc) in enumerate(data['tools'], 1):
        if check_tool(tool_name):
            status = "✓"
            color = "\033[92m"  # Green
        else:
            status = "✗"
            color = "\033[91m"  # Red
        reset = "\033[0m"
        
        print(f"  {idx:2}. {color}{status}{reset} {tool_name:<20} - {desc}")
    
    print("\n" + "=" * 80)
    print(f"Total: {len(data['tools'])} tools")
    print("=" * 80 + "\n")


def search_tools(query: str):
    """Search for tools"""
    query = query.lower()
    results = []
    
    for category, data in KALI_TOOLS.items():
        for tool_name, desc in data['tools']:
            if query in tool_name.lower() or query in desc.lower():
                results.append((tool_name, category, desc, check_tool(tool_name)))
    
    print(f"\n{'='*80}")
    print(f"Search results for '{query}': {len(results)} found")
    print(f"{'='*80}\n")
    
    for tool_name, category, desc, installed in results:
        status = "✓" if installed else "✗"
        print(f"  {status} {tool_name:<20} [{category}] - {desc}")
    
    print(f"\n{'='*80}\n")


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == '--list':
            print_tool_list()
        elif sys.argv[1] == '--compact':
            print_compact_menu()
        elif sys.argv[1] == '--category' and len(sys.argv) > 2:
            print_category_tools(sys.argv[2])
        elif sys.argv[1] == '--search' and len(sys.argv) > 2:
            search_tools(sys.argv[2])
        else:
            print("Usage: python3 kali_tools_list.py [OPTION]")
            print("  --list              Show complete tool listing")
            print("  --compact           Show compact start menu")
            print("  --category NAME     Show tools in category")
            print("  --search QUERY      Search for tools")
    else:
        print_compact_menu()
