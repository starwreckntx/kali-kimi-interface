# Kali Linux Interactive Start Menu

A comprehensive text-based menu system for Kali Linux CLI tools.

## Files Created

| File | Purpose | Size |
|------|---------|------|
| `kali_start_menu.py` | Interactive menu system with navigation | 26KB |
| `kali_tools_list.py` | Tool catalog and listing utilities | 14KB |
| `KALI_START_MENU_GUIDE.md` | This documentation file | - |

---

## Features

### 1. Interactive Start Menu (`kali_start_menu.py`)

A full-featured interactive menu with:
- **14 Categories** covering all Kali Linux tools
- **Dynamic tool detection** - shows ✓ for installed tools
- **Multi-level navigation** - browse categories and tools
- **Tool execution** - launch tools with custom arguments
- **Search functionality** - find tools by name or description
- **Terminal integration** - open shells without leaving menu
- **System information** - view OS and network details

### 2. Tool Catalog (`kali_tools_list.py`)

Multiple view modes:
- **Compact menu** - Start menu style listing
- **Full listing** - All tools with install status
- **Category view** - Tools organized by category
- **Search** - Find specific tools

---

## Tool Categories

| # | Category | Tools | Icon |
|---|----------|-------|------|
| 1 | Information Gathering | 15 | 🔍 |
| 2 | Vulnerability Analysis | 9 | 🔎 |
| 3 | Web Applications | 18 | 🌐 |
| 4 | Password Attacks | 12 | 🔐 |
| 5 | Wireless Attacks | 15 | 📡 |
| 6 | Exploitation | 9 | 💥 |
| 7 | Sniffing & Spoofing | 14 | 👃 |
| 8 | Forensics | 12 | 🔬 |
| 9 | Reverse Engineering | 12 | 🔧 |
| 10 | Mobile Analysis | 9 | 📱 |
| 11 | Social Engineering | 7 | 🎭 |
| 12 | Steganography | 7 | 📷 |
| 13 | Reporting | 7 | 📊 |
| 14 | System Services | 13 | ⚙️ |

**Total: 159 tools in database**

---

## Usage

### Interactive Menu

```bash
# Launch the interactive menu
python3 kali_start_menu.py
```

**Navigation:**
```
Main Menu:
  1-14  Select category
  S     Search for tool
  I     System information
  T     Open terminal
  Q     Quit

Category Menu:
  1-N   Select tool
  B     Back to main
  H     Show help
  T     Open terminal
```

### Tool Catalog Commands

```bash
# Show compact start menu
python3 kali_tools_list.py --compact

# Show complete tool listing
python3 kali_tools_list.py --list

# Show specific category
python3 kali_tools_list.py --category "Web Applications"

# Search for tools
python3 kali_tools_list.py --search "sql"
```

---

## Installed vs Available Tools

The menu automatically detects which tools are installed and shows:
- **✓** - Tool is installed and ready
- **✗ or blank** - Tool not installed (can be installed via apt)

### Installing Missing Tools

```bash
# Single tool
sudo apt install -y <tool-name>

# Category (example: web tools)
sudo apt install -y zaproxy padbuster uniscan xsser arachni

# All missing tools
sudo apt update
sudo apt install -y kali-linux-everything
```

---

## Sample Output

### Compact Menu
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         KALI LINUX START MENU                                ║
╠══════════════════════════════════════════════════════════════════════════════╣
║   1. 🔍 Information Gathering      [12/15]                                    ║
║   2. 🔎 Vulnerability Analysis       [4/9]                                    ║
║   3. 🌐 Web Applications           [10/18]                                    ║
║   ...                                                                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  S. Search Tool  │  I. System Info  │  T. Terminal  │  Q. Quit               ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Category View
```
🌐 WEB APPLICATIONS
================================================================================
   1. ✓ burpsuite            - Web proxy
   2. ✗ zaproxy              - OWASP ZAP
   3. ✓ gobuster             - Dir brute-forcer
   4. ✓ dirb                 - Web scanner
   ...
================================================================================
Total: 18 tools
```

---

## Key Tools by Category

### Information Gathering
- **nmap** - Network discovery and security auditing
- **masscan** - Internet-scale port scanner
- **theHarvester** - Email harvesting and subdomain discovery
- **recon-ng** - Full-featured reconnaissance framework
- **dnsrecon** - DNS enumeration and scanning

### Vulnerability Analysis
- **nikto** - Web server vulnerability scanner
- **sqlmap** - Automatic SQL injection tool
- **openvas** - Vulnerability scanning framework
- **lynis** - Security auditing tool

### Web Applications
- **burpsuite** - Web vulnerability scanner and proxy
- **gobuster** - Directory/file brute-forcer
- **wfuzz** - Web application fuzzer
- **ffuf** - Fast web fuzzer
- **wpscan** - WordPress vulnerability scanner

### Password Attacks
- **john** - John the Ripper password cracker
- **hydra** - Network login cracker
- **hashcat** - World's fastest password cracker
- **crunch** - Wordlist generator

### Wireless Attacks
- **aircrack-ng** - WiFi security auditing suite
- **wifite** - Automated wireless auditor
- **reaver** - WPS PIN brute-forcer
- **kismet** - Wireless network detector

### Exploitation
- **metasploit** (msfconsole) - Exploitation framework
- **searchsploit** - Exploit database searcher
- **beef-xss** - Browser exploitation framework
- **setoolkit** - Social engineering toolkit

### Sniffing & Spoofing
- **wireshark** - Network protocol analyzer
- **ettercap** - Man-in-the-middle attack suite
- **bettercap** - Network attack and monitoring
- **responder** - LLMNR, NBT-NS and MDNS poisoner

### Forensics
- **autopsy** - Digital forensics platform
- **binwalk** - Firmware analysis tool
- **volatility** - Memory forensics framework
- **foremost** - File recovery tool

---

## Customization

### Adding New Tools

Edit `kali_tools_list.py` and add to the `KALI_TOOLS` dictionary:

```python
'New Category': {
    'icon': '🆕',
    'description': 'Description here',
    'tools': [
        ('toolname', 'Tool description'),
        ('anothertool', 'Another description'),
    ]
}
```

### Modifying Colors

Edit the `COLORS` dictionary in `kali_start_menu.py`:

```python
COLORS = {
    'reset': '\033[0m',
    'green': '\033[92m',
    'red': '\033[91m',
    'blue': '\033[94m',
    # Add your own
}
```

---

## Integration with Claw Harness

These menus can be integrated with the claw harness tool system:

```python
# In harness_integration.py, add:
from kali_start_menu import KaliStartMenu

def launch_kali_menu():
    menu = KaliStartMenu()
    menu.run()
```

Or as a new tool:
```python
ToolSpec {
    name: "kali_menu",
    description: "Launch Kali Linux tools menu",
    input_schema: json!({}),
    required_permission: PermissionMode::ReadOnly,
}
```

---

## Requirements

- Python 3.6+
- Terminal with UTF-8 support (for icons)
- Optional: Color support for best experience

---

## Troubleshooting

### Menu won't display
```bash
# Check Python version
python3 --version

# Run with explicit Python
python3 kali_start_menu.py
```

### Colors not showing
Your terminal may not support ANSI colors. The menu works without colors.

### Tools show as not installed
```bash
# Refresh tool cache
which <tool-name>

# Install missing tools
sudo apt install -y <tool-name>
```

---

## License

These menu systems are created as part of the claw harness adaptation for Kali Linux.

---

**Created**: 2026-04-10
**Version**: 1.0.0
**Status**: Ready for use
