# Kali Kimi Interface (KKI)

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-blue.svg)](https://www.kali.org/)
[![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity-red.svg)](https://en.wikipedia.org/wiki/Computer_security)

A comprehensive text-based interface system for Kali Linux penetration testing tools, designed for AI assistants and cybersecurity professionals.

![Kali Linux](https://www.kali.org/images/kali-logo.svg)

## 🎯 Overview

Kali Kimi Interface (KKI) provides an intuitive, interactive menu system for accessing Kali Linux's extensive suite of cybersecurity tools. Built for both human operators and AI agents, KKI simplifies tool discovery, execution, and automation.

### Key Features

- **🎮 Interactive Start Menu** - Navigate 159+ security tools through an intuitive text interface
- **🔍 Smart Tool Discovery** - Automatic detection of installed vs available tools
- **🤖 AI-Ready** - Structured JSON output for AI integration and automation
- **🔒 Security First** - Input validation and safe command execution
- **📊 Network Mapping** - Built-in network discovery and visualization
- **📱 Multi-Platform** - Works on any terminal with Python 3.6+

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/starwreckntx/kali-kimi-interface.git
cd kali-kimi-interface

# Run the interactive menu
python3 kali_start_menu.py

# Or use the quick catalog
python3 kali_tools_list.py --compact
```

## 📁 Project Structure

```
kali-kimi-interface/
├── kali_start_menu.py          # Interactive menu system (26KB)
├── kali_tools_list.py          # Tool catalog & listing (14KB)
├── src/
│   ├── kali_tools.py           # Security tool adapters
│   ├── harness_integration.py  # Framework integration
│   └── network_mapper.py       # Network discovery
├── tests/
│   └── test_kali_tools.py      # Test suite (29 tests)
├── docs/
│   └── KALI_START_MENU_GUIDE.md # Documentation
└── README.md                   # This file
```

## 🛠️ Installation

### Requirements

- Python 3.6 or higher
- Kali Linux (recommended) or any Linux distribution
- Terminal with UTF-8 support

### Install on Kali Linux

```bash
# Install dependencies
sudo apt update
sudo apt install -y python3 python3-pip

# Clone repository
git clone https://github.com/starwreckntx/kali-kimi-interface.git
cd kali-kimi-interface

# Run
python3 kali_start_menu.py
```

### Install Missing Tools

The menu shows which tools are installed (✓) vs missing (✗). Install all at once:

```bash
# Install all Kali Linux tools
sudo apt install -y kali-linux-everything

# Or install specific categories
sudo apt install -y kali-linux-information-gathering
sudo apt install -y kali-linux-web
sudo apt install -y kali-linux-wireless
```

## 📖 Usage

### Interactive Menu

Launch the full interactive menu:

```bash
python3 kali_start_menu.py
```

**Navigation:**
- `1-14` - Select tool category
- `S` - Search for specific tools
- `I` - View system information
- `T` - Open terminal
- `Q` - Quit

### Tool Catalog

Non-interactive tool listing:

```bash
# Show compact menu
python3 kali_tools_list.py --compact

# Show complete listing
python3 kali_tools_list.py --list

# Show specific category
python3 kali_tools_list.py --category "Web Applications"

# Search for tools
python3 kali_tools_list.py --search "sql"
```

### Python API

Use the interface programmatically:

```python
from src.harness_integration import SecurityToolExecutor

executor = SecurityToolExecutor()

# List available tools
tools = executor.list_tools()

# Execute nmap scan
result = executor.execute('nmap_scan', {
    'target': '192.168.1.1',
    'scan_type': 'syn',
    'ports': '1-1000'
})

print(result)
```

### Network Mapping

```python
from src.network_mapper import NetworkMapper

mapper = NetworkMapper()

# Discover devices
devices = mapper.discover_ethernet_devices('192.168.1.0/24')

# Generate report
report = mapper.generate_network_map()

# Save to file
mapper.save_map('network_map.json')
```

## 🧰 Tool Categories

| Category | Tools | Description |
|----------|-------|-------------|
| 🔍 Information Gathering | 15 | nmap, masscan, recon-ng, theHarvester |
| 🔎 Vulnerability Analysis | 9 | nikto, sqlmap, openvas, lynis |
| 🌐 Web Applications | 18 | burpsuite, gobuster, wfuzz, wpscan |
| 🔐 Password Attacks | 12 | john, hydra, hashcat, crunch |
| 📡 Wireless Attacks | 15 | aircrack-ng, wifite, reaver, kismet |
| 💥 Exploitation | 9 | metasploit, searchsploit, beef-xss |
| 👃 Sniffing & Spoofing | 14 | wireshark, ettercap, bettercap |
| 🔬 Forensics | 12 | autopsy, volatility, binwalk |
| 🔧 Reverse Engineering | 12 | radare2, gdb, ghidra |
| 📱 Mobile Analysis | 9 | apktool, frida, objection |
| 🎭 Social Engineering | 7 | setoolkit, gophish |
| 📷 Steganography | 7 | steghide, zsteg |
| 📊 Reporting | 7 | dradis, keepnote |
| ⚙️ System Services | 13 | apache2, nginx, openvpn |

**Total: 159 tools in database**

## 🤖 AI Integration

Kali Kimi Interface is designed for AI agents and automation:

### Structured Output

All tool executions return JSON:

```json
{
  "tool": "nmap",
  "command": "nmap -sS -p 1-1000 192.168.1.1",
  "returncode": 0,
  "parsed_output": {
    "hosts": [
      {
        "ip": "192.168.1.1",
        "mac": "f4:52:46:7a:e1:8b",
        "ports": [
          {"port": "22", "state": "open", "service": "ssh"},
          {"port": "80", "state": "open", "service": "http"}
        ]
      }
    ]
  }
}
```

### Safety Features

- **Input validation** - Prevents command injection
- **Rate limiting** - Prevents abuse
- **Timeout controls** - Long-running operations
- **Sandboxed execution** - Controlled environment

### Example: AI Agent Usage

```python
from src.kali_tools import KaliToolAdapter

adapter = KaliToolAdapter()

# Safe, validated scan
result = adapter.nmap_scan(
    target="192.168.1.1",
    scan_type="syn",
    ports="1-1000"
)

# Structured data for AI analysis
print(result.parsed_output)
```

## 🧪 Testing

Run the test suite:

```bash
# Install pytest
pip3 install pytest

# Run tests
python3 -m pytest tests/test_kali_tools.py -v
```

**Test Coverage:**
- Input validation (9 tests)
- Command injection prevention (4 tests)
- Output parsing (8 tests)
- Rate limiting (2 tests)
- Integration tests (6 tests)

**Total: 29 tests**

## 🤝 Contributing

We welcome contributions! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Commit** your changes: `git commit -m 'Add amazing feature'`
4. **Push** to the branch: `git push origin feature/amazing-feature`
5. **Open** a Pull Request

### Areas for Contribution

- Add new tool categories
- Improve output parsers
- Enhance AI integration
- Add GUI interface
- Create documentation
- Translate to other languages

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Kali Linux](https://www.kali.org/) - The premier penetration testing platform
- [Claw Harness](https://github.com/instructkr/claw-code) - Inspiration for tool integration
- [Offensive Security](https://www.offensive-security.com/) - Creators of Kali Linux

## 📞 Contact

- **GitHub Issues**: For bug reports and feature requests
- **Discussions**: For questions and ideas
- **Email**: Open an issue for private inquiries

## 🌟 Star History

If you find this project useful, please consider starring it on GitHub!

## 🔗 Related Projects

- [Kali Linux](https://www.kali.org/) - Penetration Testing Distribution
- [Metasploit](https://www.metasploit.com/) - Exploitation Framework
- [Burp Suite](https://portswigger.net/burp) - Web Security Testing

---

**Disclaimer**: This tool is intended for authorized security testing and educational purposes only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

---

Made with ❤️ for the cybersecurity community
