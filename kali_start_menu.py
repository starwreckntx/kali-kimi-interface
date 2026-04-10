#!/usr/bin/env python3
"""
Kali Linux Interactive Start Menu
A comprehensive text-based menu system for Kali CLI tools
"""

import os
import sys
import subprocess
import shutil
from typing import Dict, List, Tuple, Optional

# Menu styling
COLORS = {
    'reset': '\033[0m',
    'bold': '\033[1m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'red': '\033[91m',
    'blue': '\033[94m',
    'cyan': '\033[96m',
    'magenta': '\033[95m',
    'white': '\033[97m',
    'bg_black': '\033[40m',
    'bg_green': '\033[42m',
    'bg_blue': '\033[44m',
}

class KaliStartMenu:
    """Interactive menu for Kali Linux tools"""
    
    def __init__(self):
        self.running = True
        self.current_menu = 'main'
        self.menu_history = []
        self.tools = self._build_tool_database()
        
    def _color(self, text: str, color: str) -> str:
        """Apply color to text"""
        return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"
    
    def _clear(self):
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def _build_tool_database(self) -> Dict:
        """Build database of Kali tools organized by category"""
        return {
            'information_gathering': {
                'name': 'Information Gathering',
                'description': 'Reconnaissance and information collection tools',
                'icon': '🔍',
                'tools': [
                    ('nmap', 'Network Mapper - Port scanning and OS detection', 'nmap -h'),
                    ('masscan', 'Fast TCP port scanner', 'masscan --help'),
                    ('theHarvester', 'Email harvesting and subdomain discovery', 'theHarvester -h'),
                    ('dnsrecon', 'DNS enumeration and scanning', 'dnsrecon -h'),
                    ('dnsenum', 'DNS enumeration tool', 'dnsenum --help'),
                    ('fierce', 'DNS enumeration and subdomain discovery', 'fierce -h'),
                    ('dmitry', 'Deepmagic Information Gathering Tool', 'dmitry -h'),
                    ('ike-scan', 'IKE/IPSec VPN scanning', 'ike-scan -h'),
                    ('netdiscover', 'Network address discovery', 'netdiscover -h'),
                    ('p0f', 'Passive OS fingerprinting', 'p0f -h'),
                    ('recon-ng', 'Web reconnaissance framework', 'recon-ng --help'),
                    ('maltego', 'Open source intelligence tool', 'maltego'),
                ]
            },
            'vulnerability_analysis': {
                'name': 'Vulnerability Analysis',
                'description': 'Scan for vulnerabilities and weaknesses',
                'icon': '🔎',
                'tools': [
                    ('nikto', 'Web server vulnerability scanner', 'nikto -H'),
                    ('sqlmap', 'Automated SQL injection tool', 'sqlmap -h'),
                    ('openvas', 'Vulnerability scanning framework', 'openvas --help'),
                    ('legion', 'Semi-automatic penetration testing', 'legion'),
                    ('sparta', 'Network infrastructure penetration testing', 'sparta'),
                    ('lynis', 'Security auditing tool', 'lynis --help'),
                    ('unix-privesc-check', 'Unix privilege escalation checker', 'unix-privesc-check'),
                ]
            },
            'web_applications': {
                'name': 'Web Application Analysis',
                'description': 'Web app testing and exploitation',
                'icon': '🌐',
                'tools': [
                    ('burpsuite', 'Web vulnerability scanner and proxy', 'burpsuite'),
                    ('zaproxy', 'OWASP ZAP web app scanner', 'zaproxy'),
                    ('gobuster', 'Directory/file brute-forcer', 'gobuster -h'),
                    ('dirb', 'Web content scanner', 'dirb'),
                    ('wfuzz', 'Web application fuzzer', 'wfuzz --help'),
                    ('ffuf', 'Fast web fuzzer', 'ffuf -h'),
                    ('wpscan', 'WordPress vulnerability scanner', 'wpscan --help'),
                    ('commix', 'Command injection exploiter', 'commix -h'),
                    ('whatweb', 'Web scanner and fingerprinting', 'whatweb -h'),
                    ('wafw00f', 'Web Application Firewall detector', 'wafw00f -h'),
                    ('padbuster', 'Padding Oracle exploit', 'padbuster'),
                    ('skipfish', 'Web application security scanner', 'skipfish -h'),
                    ('uniscan', 'Remote file inclusion scanner', 'uniscan'),
                    ('xsser', 'Cross-site scripting scanner', 'xsser -h'),
                ]
            },
            'password_attacks': {
                'name': 'Password Attacks',
                'description': 'Password cracking and brute force tools',
                'icon': '🔐',
                'tools': [
                    ('john', 'John the Ripper password cracker', 'john --help'),
                    ('hydra', 'Network login cracker', 'hydra -h'),
                    ('hashcat', 'Worlds fastest password cracker', 'hashcat --help'),
                    ('medusa', 'Speedy brute-forcer', 'medusa -h'),
                    ('ncrack', 'Network authentication cracker', 'ncrack -h'),
                    ('crunch', 'Wordlist generator', 'crunch --help'),
                    ('cewl', 'Custom wordlist generator', 'cewl --help'),
                    ('hash-identifier', 'Hash identification tool', 'hash-identifier'),
                    ('rainbowcrack', 'Rainbow table password cracker', 'rcrack'),
                    ('brutespray', 'Brute force services from Nmap output', 'brutespray -h'),
                ]
            },
            'wireless_attacks': {
                'name': 'Wireless Attacks',
                'description': 'WiFi and wireless network tools',
                'icon': '📡',
                'tools': [
                    ('aircrack-ng', 'WiFi security auditing', 'aircrack-ng --help'),
                    ('aireplay-ng', 'Packet injection tool', 'aireplay-ng --help'),
                    ('airodump-ng', 'Packet capture tool', 'airodump-ng --help'),
                    ('airmon-ng', 'Monitor mode management', 'airmon-ng --help'),
                    ('wifite', 'Automated wireless auditor', 'wifite --help'),
                    ('reaver', 'WPS PIN brute-forcer', 'reaver -h'),
                    ('bully', 'WPS brute-forcer', 'bully -h'),
                    ('kismet', 'Wireless network detector', 'kismet -h'),
                    ('cowpatty', 'WPA/WPA2 brute-forcer', 'cowpatty -h'),
                    ('eapmd5pass', 'EAP-MD5 dictionary attack', 'eapmd5pass'),
                    ('fern-wifi-cracker', 'WiFi security auditing', 'fern-wifi-cracker'),
                    ('spooftooph', 'Bluetooth spoofing', 'spooftooph'),
                ]
            },
            'exploitation': {
                'name': 'Exploitation Tools',
                'description': 'Exploit development and delivery',
                'icon': '💥',
                'tools': [
                    ('metasploit', 'Exploitation framework', 'msfconsole -h'),
                    ('msfvenom', 'Payload generator', 'msfvenom -h'),
                    ('searchsploit', 'Exploit database searcher', 'searchsploit -h'),
                    ('beef-xss', 'Browser exploitation framework', 'beef-xss'),
                    ('commix', 'Command injection exploiter', 'commix -h'),
                    ('routersploit', 'Router exploitation framework', 'routersploit'),
                    ('setoolkit', 'Social engineering toolkit', 'setoolkit'),
                    ('shellnoob', 'Shellcode writing toolkit', 'shellnoob'),
                ]
            },
            'sniffing_spoofing': {
                'name': 'Sniffing & Spoofing',
                'description': 'Network traffic analysis and manipulation',
                'icon': '👃',
                'tools': [
                    ('wireshark', 'Network protocol analyzer', 'wireshark -h'),
                    ('tshark', 'CLI network analyzer', 'tshark -h'),
                    ('tcpdump', 'Packet analyzer', 'tcpdump -h'),
                    ('ettercap', 'Man-in-the-middle attacks', 'ettercap -h'),
                    ('bettercap', 'Network attack tool', 'bettercap -h'),
                    ('driftnet', 'Image sniffer', 'driftnet -h'),
                    ('urlsnarf', 'URL sniffer', 'urlsnarf -h'),
                    ('msgsnarf', 'Message sniffer', 'msgsnarf -h'),
                    ('dnsspoof', 'DNS spoofing tool', 'dnsspoof -h'),
                    ('arpspoof', 'ARP spoofing tool', 'arpspoof -h'),
                    ('ssldump', 'SSL/TLS analyzer', 'ssldump -h'),
                    ('macchanger', 'MAC address changer', 'macchanger -h'),
                ]
            },
            'forensics': {
                'name': 'Forensics Tools',
                'description': 'Digital forensics and investigation',
                'icon': '🔬',
                'tools': [
                    ('autopsy', 'Digital forensics platform', 'autopsy -h'),
                    ('binwalk', 'Firmware analysis tool', 'binwalk -h'),
                    ('bulk_extractor', 'Forensic data extractor', 'bulk_extractor -h'),
                    (' foremost', 'File recovery tool', 'foremost -h'),
                    ('volatility', 'Memory forensics framework', 'volatility -h'),
                    ('pdf-parser', 'PDF analysis tool', 'pdf-parser -h'),
                    ('pdfid', 'PDF malware scanner', 'pdfid -h'),
                    ('peepdf', 'PDF analysis framework', 'peepdf -h'),
                    ('regripper', 'Windows registry tool', 'regripper'),
                    ('chkrootkit', 'Rootkit detector', 'chkrootkit -h'),
                    ('rkhunter', 'Rootkit hunter', 'rkhunter -h'),
                ]
            },
            'reverse_engineering': {
                'name': 'Reverse Engineering',
                'description': 'Binary analysis and debugging',
                'icon': '🔧',
                'tools': [
                    ('gdb', 'GNU debugger', 'gdb --help'),
                    ('radare2', 'Reverse engineering framework', 'radare2 -h'),
                    ('ghidra', 'Software reverse engineering', 'ghidra'),
                    ('ida-free', 'Interactive disassembler', 'ida64'),
                    ('apktool', 'Android APK tool', 'apktool -h'),
                    ('dex2jar', 'Android DEX to JAR', 'dex2jar'),
                    ('jd-gui', 'Java decompiler', 'jd-gui'),
                    ('valgrind', 'Memory debugger', 'valgrind --help'),
                    ('strace', 'System call tracer', 'strace -h'),
                    ('ltrace', 'Library call tracer', 'ltrace -h'),
                ]
            },
            'reporting': {
                'name': 'Reporting Tools',
                'description': 'Documentation and report generation',
                'icon': '📊',
                'tools': [
                    ('dradis', 'Collaborative reporting', 'dradis'),
                    ('keepnote', 'Note taking application', 'keepnote'),
                    ('cutycapt', 'Web page screenshot', 'cutycapt --help'),
                    ('recordmydesktop', 'Screen recorder', 'recordmydesktop -h'),
                    ('magictree', 'Data management tool', 'magictree'),
                ]
            },
            'system_services': {
                'name': 'System & Services',
                'description': 'System utilities and services',
                'icon': '⚙️',
                'tools': [
                    ('apache2', 'Web server', 'apache2 -h'),
                    ('nginx', 'Web server', 'nginx -h'),
                    ('ssh', 'OpenSSH client/server', 'ssh -h'),
                    ('openvpn', 'VPN solution', 'openvpn --help'),
                    ('proxychains', 'Proxy chains', 'proxychains -h'),
                    ('tmux', 'Terminal multiplexer', 'tmux -h'),
                    ('screen', 'Terminal multiplexer', 'screen -h'),
                    ('htop', 'Process viewer', 'htop -h'),
                    ('iftop', 'Network bandwidth monitor', 'iftop -h'),
                    ('nethogs', 'Network traffic monitor', 'nethogs -h'),
                ]
            },
        }
    
    def _check_tool(self, tool_name: str) -> Tuple[bool, str]:
        """Check if a tool is installed and return path"""
        tool_path = shutil.which(tool_name)
        if tool_path:
            return True, tool_path
        # Try common variations
        variations = [
            tool_name.replace('-', ''),
            tool_name.replace('_', '-'),
            f'{tool_name}.py',
            tool_name.lower(),
        ]
        for var in variations:
            path = shutil.which(var)
            if path:
                return True, path
        return False, ''
    
    def _draw_header(self, title: str = "KALI LINUX START MENU"):
        """Draw the menu header"""
        width = 70
        print()
        print(self._color('╔' + '═' * width + '╗', 'blue'))
        print(self._color('║', 'blue') + self._color(f'{title:^{width}}', 'green') + self._color('║', 'blue'))
        print(self._color('╠' + '═' * width + '╣', 'blue'))
    
    def _draw_footer(self, options: str = ""):
        """Draw the menu footer"""
        width = 70
        if options:
            print(self._color('╠' + '═' * width + '╣', 'blue'))
            print(self._color('║', 'blue') + f' {options:<{width-1}}' + self._color('║', 'blue'))
        print(self._color('╚' + '═' * width + '╝', 'blue'))
        print()
    
    def _draw_main_menu(self):
        """Draw the main category menu"""
        self._clear()
        self._draw_header("KALI LINUX START MENU")
        
        print(self._color('║', 'blue') + ' ' + self._color('Select a category:', 'yellow') + ' ' * 50 + self._color('║', 'blue'))
        print(self._color('╠' + '═' * 70 + '╣', 'blue'))
        
        idx = 1
        for key, category in self.tools.items():
            icon = category.get('icon', '•')
            name = category['name']
            desc = category['description'][:35] + '...' if len(category['description']) > 35 else category['description']
            
            # Check if any tools in category are installed
            installed_count = sum(1 for tool, _, _ in category['tools'] if self._check_tool(tool)[0])
            total_count = len(category['tools'])
            status = self._color(f'✓ {installed_count}/{total_count}', 'green') if installed_count > 0 else self._color('✗', 'red')
            
            line = f" {idx:2}. {icon} {name:<25} {status:>12}  │"
            print(self._color('║', 'blue') + self._color(line[:71], 'white') + self._color('║', 'blue'))
            idx += 1
        
        print(self._color('╠' + '═' * 70 + '╣', 'blue'))
        print(self._color('║', 'blue') + '  S. Search Tool' + ' ' * 55 + self._color('║', 'blue'))
        print(self._color('║', 'blue') + '  I. System Info' + ' ' * 55 + self._color('║', 'blue'))
        print(self._color('║', 'blue') + '  T. Terminal' + ' ' * 58 + self._color('║', 'blue'))
        print(self._color('║', 'blue') + '  Q. Quit' + ' ' * 62 + self._color('║', 'blue'))
        self._draw_footer("Enter number or letter")
    
    def _draw_category_menu(self, category_key: str):
        """Draw a category's tool menu"""
        category = self.tools[category_key]
        self._clear()
        self._draw_header(f"{category['icon']} {category['name'].upper()}")
        
        print(self._color('║', 'blue') + ' ' + self._color(category['description'], 'cyan') + ' ' * (69 - len(category['description'])) + self._color('║', 'blue'))
        print(self._color('╠' + '═' * 70 + '╣', 'blue'))
        
        idx = 1
        for tool_name, description, _ in category['tools']:
            installed, path = self._check_tool(tool_name)
            
            if installed:
                status = self._color('✓', 'green')
                color = 'white'
            else:
                status = self._color('✗', 'red')
                color = 'red'
            
            # Truncate description
            desc = description[:50] + '...' if len(description) > 50 else description
            line = f" {idx:2}. {status} {tool_name:<20} {desc}"
            line = line[:69] + ' │'
            print(self._color('║', 'blue') + self._color(line, color) + self._color('║', 'blue'))
            idx += 1
        
        print(self._color('╠' + '═' * 70 + '╣', 'blue'))
        print(self._color('║', 'blue') + '  B. Back to Main Menu' + ' ' * 48 + self._color('║', 'blue'))
        print(self._color('║', 'blue') + '  H. Show Help' + ' ' * 57 + self._color('║', 'blue'))
        print(self._color('║', 'blue') + '  T. Terminal' + ' ' * 58 + self._color('║', 'blue'))
        self._draw_footer(f"Select 1-{len(category['tools'])}, or B/H/T")
    
    def _show_system_info(self):
        """Show system information"""
        self._clear()
        self._draw_header("SYSTEM INFORMATION")
        
        info = []
        
        # OS Info
        try:
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        info.append(('OS', line.split('=')[1].strip().strip('"')))
                        break
        except:
            info.append(('OS', 'Unknown'))
        
        # Kernel
        try:
            result = subprocess.run(['uname', '-r'], capture_output=True, text=True)
            info.append(('Kernel', result.stdout.strip()))
        except:
            pass
        
        # Architecture
        try:
            result = subprocess.run(['uname', '-m'], capture_output=True, text=True)
            info.append(('Architecture', result.stdout.strip()))
        except:
            pass
        
        # Network
        try:
            result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
            ips = result.stdout.strip().split()
            info.append(('IP Addresses', ', '.join(ips[:3])))
        except:
            pass
        
        # Tool counts
        total_tools = sum(len(cat['tools']) for cat in self.tools.values())
        installed_tools = sum(
            1 for cat in self.tools.values() 
            for tool, _, _ in cat['tools'] 
            if self._check_tool(tool)[0]
        )
        info.append(('Tools', f'{installed_tools}/{total_tools} installed'))
        
        for label, value in info:
            line = f" {label:<15} {value}"
            print(self._color('║', 'blue') + line[:70] + ' ' * (70 - len(line)) + self._color('║', 'blue'))
        
        print(self._color('╠' + '═' * 70 + '╣', 'blue'))
        print(self._color('║', 'blue') + '  Press Enter to continue...' + ' ' * 43 + self._color('║', 'blue'))
        self._draw_footer()
        input()
    
    def _search_tool(self):
        """Search for a specific tool"""
        self._clear()
        self._draw_header("SEARCH TOOLS")
        
        print(self._color('║', 'blue') + ' Enter search term: ' + ' ' * 51 + self._color('║', 'blue'))
        print(self._color('╚' + '═' * 70 + '╝', 'blue'))
        print()
        
        search = input(self._color(" > ", 'green')).lower()
        if not search:
            return
        
        results = []
        for cat_key, category in self.tools.items():
            for tool_name, description, _ in category['tools']:
                if search in tool_name.lower() or search in description.lower():
                    installed, path = self._check_tool(tool_name)
                    results.append((tool_name, category['name'], description, installed, path))
        
        self._clear()
        self._draw_header(f"SEARCH RESULTS: '{search}'")
        
        if results:
            print(self._color('║', 'blue') + f' Found {len(results)} result(s):' + ' ' * (55 - len(str(len(results)))) + self._color('║', 'blue'))
            print(self._color('╠' + '═' * 70 + '╣', 'blue'))
            
            for idx, (tool, cat, desc, installed, path) in enumerate(results[:10], 1):
                status = self._color('✓', 'green') if installed else self._color('✗', 'red')
                line = f" {idx}. {status} {tool:<20} [{cat}]"
                print(self._color('║', 'blue') + line[:70] + self._color('║', 'blue'))
                
                # Show description on next line
                desc_line = f"    {desc[:60]}"
                print(self._color('║', 'blue') + self._color(desc_line[:70], 'cyan') + self._color('║', 'blue'))
                
                if installed:
                    path_line = f"    Path: {path}"
                    print(self._color('║', 'blue') + self._color(path_line[:70], 'yellow') + self._color('║', 'blue'))
                print(self._color('║', 'blue') + ' ' * 70 + self._color('║', 'blue'))
        else:
            print(self._color('║', 'blue') + ' No results found.' + ' ' * 55 + self._color('║', 'blue'))
        
        print(self._color('╠' + '═' * 70 + '╣', 'blue'))
        print(self._color('║', 'blue') + ' Press Enter to continue...' + ' ' * 43 + self._color('║', 'blue'))
        self._draw_footer()
        input()
    
    def _run_tool(self, category_key: str, tool_index: int):
        """Run a specific tool"""
        category = self.tools[category_key]
        if 0 <= tool_index < len(category['tools']):
            tool_name, description, help_cmd = category['tools'][tool_index]
            installed, path = self._check_tool(tool_name)
            
            if not installed:
                print(f"\n{self._color('✗', 'red')} Tool '{tool_name}' is not installed!")
                print(f"Install with: {self._color('sudo apt install ' + tool_name, 'yellow')}")
                input("\nPress Enter to continue...")
                return
            
            self._clear()
            print(f"\n{self._color('▶', 'green')} Launching {self._color(tool_name, 'cyan')}...")
            print(f"  {description}\n")
            
            # Show help first, then offer to run interactively
            print(self._color("Help output:", 'yellow'))
            print("-" * 70)
            
            try:
                subprocess.run(help_cmd.split(), timeout=5)
            except:
                pass
            
            print("-" * 70)
            print(f"\n{self._color('?', 'yellow')} Run {tool_name} with custom arguments? (y/n): ", end='')
            
            choice = input().lower()
            if choice == 'y':
                print(f"\nEnter arguments for {tool_name}:")
                print(f"Example: {self._color(help_cmd.split(' ', 1)[1] if ' ' in help_cmd else '', 'cyan')}")
                args = input(f"{tool_name} ")
                
                full_cmd = f"{path} {args}"
                print(f"\n{self._color('▶ Executing:', 'green')} {full_cmd}\n")
                
                try:
                    subprocess.run(full_cmd, shell=True)
                except Exception as e:
                    print(f"Error: {e}")
                
                input("\nPress Enter to continue...")
    
    def _open_terminal(self):
        """Open a terminal"""
        self._clear()
        print(self._color("\n▶ Opening terminal...", 'green'))
        print(self._color("  Type 'exit' to return to the menu\n", 'yellow'))
        
        try:
            # Try to preserve menu context
            shell = os.environ.get('SHELL', '/bin/bash')
            subprocess.run([shell, '-i'])
        except:
            pass
    
    def run(self):
        """Main menu loop"""
        while self.running:
            if self.current_menu == 'main':
                self._draw_main_menu()
                choice = input(self._color("\n > ", 'green')).strip().lower()
                
                if choice == 'q':
                    self.running = False
                elif choice == 's':
                    self._search_tool()
                elif choice == 'i':
                    self._show_system_info()
                elif choice == 't':
                    self._open_terminal()
                elif choice.isdigit():
                    idx = int(choice) - 1
                    categories = list(self.tools.keys())
                    if 0 <= idx < len(categories):
                        self.menu_history.append(self.current_menu)
                        self.current_menu = categories[idx]
                        
            else:
                # In a category menu
                self._draw_category_menu(self.current_menu)
                choice = input(self._color("\n > ", 'green')).strip().lower()
                
                if choice == 'b':
                    if self.menu_history:
                        self.current_menu = self.menu_history.pop()
                    else:
                        self.current_menu = 'main'
                elif choice == 'h':
                    category = self.tools[self.current_menu]
                    print(f"\n{category['description']}")
                    print(f"Total tools in category: {len(category['tools'])}")
                    input("\nPress Enter to continue...")
                elif choice == 't':
                    self._open_terminal()
                elif choice.isdigit():
                    self._run_tool(self.current_menu, int(choice) - 1)
        
        self._clear()
        print(self._color("\n✓ Goodbye!\n", 'green'))


def main():
    """Entry point"""
    try:
        menu = KaliStartMenu()
        menu.run()
    except KeyboardInterrupt:
        print("\n\nGoodbye!")
        sys.exit(0)


if __name__ == '__main__':
    main()
