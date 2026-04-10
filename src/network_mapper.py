#!/usr/bin/env python3
"""
Network Mapper for Claw Harness
Combines WiFi scanning and Ethernet network discovery

Usage:
    python3 -m src.network_mapper
    python3 -m src.network_mapper --wifi wlan0
    python3 -m src.network_mapper --ethernet --scan-ports
"""

import subprocess
import json
import time
import argparse
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set
from datetime import datetime
from pathlib import Path


@dataclass
class NetworkDevice:
    ip: Optional[str]
    mac: str
    manufacturer: str
    hostname: Optional[str]
    device_type: str
    status: str
    open_ports: List[int]
    services: List[str]
    signal_dbm: Optional[int] = None  # For WiFi
    last_seen: str = ""
    first_seen: str = ""


@dataclass
class WiFiNetwork:
    bssid: str
    ssid: str
    channel: int
    encryption: str
    cipher: str
    authentication: str
    signal_dbm: int
    signal_quality: str
    clients: List[str]
    manufacturer: str
    first_seen: str
    last_seen: str


class NetworkMapper:
    """Unified network mapping tool for WiFi and Ethernet"""
    
    # Common MAC address prefixes (OUI)
    OUIS = {
        '00:26:B9': 'Dell Inc.',
        'F4:52:46': 'ARRIS Group',
        '68:72:C3': 'Samsung Electronics',
        '94:6A:B0': 'Technicolor',
        '3C:9C:0F': 'Samsung Electronics',
        'B8:2C:A0': 'Intel Corporate',
        'AC:DE:48': 'Apple Inc.',
        '00:50:56': 'VMware Inc.',
        '00:1A:11': 'Google Inc.',
        '64:16:66': 'Amazon Technologies',
        'A4:45:19': 'Xiaomi Communications',
        '00:25:00': 'Apple Inc.',
        '00:17:88': 'Philips Lighting',
        '18:B4:30': 'Nest Labs',
        '00:24:36': 'Cisco Systems',
        '00:1C:BF': 'Belkin International',
        '00:1E:C0': 'Arris Group',
        'E0:CB:BC': 'Netgear',
        '00:09:5B': 'Linksys',
        '00:14:6C': 'Netgear',
        '00:1F:33': 'Intel Corporate',
        '00:21:5C': 'Intel Corporate',
        '00:26:82': 'Cisco Systems',
        '00:50:7F': 'D-Link Corporation',
    }
    
    # Common service ports
    COMMON_PORTS = [22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080, 8443]
    
    def __init__(self):
        self.devices: Dict[str, NetworkDevice] = {}
        self.wifi_networks: Dict[str, WiFiNetwork] = {}
        self.scan_time: Optional[str] = None
    
    def get_manufacturer(self, mac: str) -> str:
        """Get manufacturer from MAC address OUI"""
        mac_upper = mac.upper()
        for oui, manufacturer in self.OUIS.items():
            if mac_upper.startswith(oui):
                return manufacturer
        return "Unknown"
    
    def discover_ethernet_devices(self, network_cidr: str = "192.168.1.0/24") -> List[NetworkDevice]:
        """
        Discover devices on Ethernet network using ARP table and ping sweep
        """
        print(f"[*] Discovering devices on {network_cidr}...")
        
        # Get ARP table
        try:
            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True,
                text=True,
                timeout=10
            )
            arp_entries = result.stdout.strip().split('\n')
        except:
            arp_entries = []
        
        # Parse ARP entries
        devices = []
        timestamp = datetime.now().isoformat()
        
        for entry in arp_entries:
            if 'FAILED' in entry:
                continue
            
            parts = entry.split()
            if len(parts) >= 5:
                ip = parts[0]
                mac = parts[4] if ':' in parts[4] else None
                
                if mac and ip and not ip.startswith('fe80') and not ':' in ip:
                    device = NetworkDevice(
                        ip=ip,
                        mac=mac,
                        manufacturer=self.get_manufacturer(mac),
                        hostname=self._resolve_hostname(ip),
                        device_type=self._guess_device_type(mac),
                        status='REACHABLE' if 'REACHABLE' in entry else 'STALE',
                        open_ports=[],
                        services=[],
                        last_seen=timestamp,
                        first_seen=timestamp
                    )
                    
                    # Check for duplicate MAC
                    if mac not in [d.mac for d in devices]:
                        devices.append(device)
                        self.devices[mac] = device
        
        return devices
    
    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Try to resolve IP to hostname"""
        try:
            result = subprocess.run(
                ["host", ip],
                capture_output=True,
                text=True,
                timeout=2
            )
            if result.returncode == 0:
                # Parse "1.2.3.4.in-addr.arpa domain name pointer hostname"
                parts = result.stdout.split()
                if len(parts) >= 5:
                    return parts[-1].rstrip('.')
        except:
            pass
        return None
    
    def _guess_device_type(self, mac: str) -> str:
        """Guess device type from MAC manufacturer"""
        manufacturer = self.get_manufacturer(mac).lower()
        
        if any(x in manufacturer for x in ['apple', 'samsung', 'xiaomi', 'google']):
            return 'Mobile/Tablet'
        elif any(x in manufacturer for x in ['dell', 'hp', 'lenovo', 'intel']):
            return 'Computer/Laptop'
        elif any(x in manufacturer for x in ['arris', 'netgear', 'cisco', 'belkin', 'd-link']):
            return 'Router/Network'
        elif any(x in manufacturer for x in ['philips', 'nest', 'amazon']):
            return 'IoT/Smart Home'
        else:
            return 'Unknown'
    
    def scan_ports(self, ip: str, ports: List[int] = None) -> List[int]:
        """Quick port scan on a single host"""
        if ports is None:
            ports = self.COMMON_PORTS
        
        open_ports = []
        
        for port in ports:
            try:
                result = subprocess.run(
                    ["nc", "-z", "-w", "1", ip, str(port)],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    open_ports.append(port)
            except:
                pass
        
        return open_ports
    
    def get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        services = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            445: 'SMB', 3389: 'RDP', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }
        return services.get(port, f'Port-{port}')
    
    def scan_wifi_networks(self, interface: str = "wlan0", duration: int = 30) -> List[WiFiNetwork]:
        """
        Scan for WiFi networks using airodump-ng
        Requires monitor mode capable interface
        """
        print(f"[*] Scanning WiFi networks on {interface}...")
        print(f"[*] Scan duration: {duration} seconds")
        
        networks = []
        
        # Check if interface exists
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if interface not in result.stdout:
                print(f"[!] Interface {interface} not found!")
                return networks
        except Exception as e:
            print(f"[!] Error checking interface: {e}")
            return networks
        
        # Put in monitor mode and scan
        mon_interface = f"{interface}mon"
        
        try:
            # Enable monitor mode
            subprocess.run(
                ["sudo", "airmon-ng", "start", interface],
                capture_output=True,
                timeout=10
            )
            
            # Run airodump-ng
            output_file = "/tmp/wifiscan"
            process = subprocess.Popen(
                [
                    "sudo", "airodump-ng",
                    "--write-interval", "1",
                    "--write", output_file,
                    "-o", "csv",
                    mon_interface
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for scan
            time.sleep(duration)
            process.terminate()
            
            # Stop monitor mode
            subprocess.run(
                ["sudo", "airmon-ng", "stop", mon_interface],
                capture_output=True,
                timeout=10
            )
            
            # Parse results
            networks = self._parse_wifi_csv(f"{output_file}-01.csv")
            
        except Exception as e:
            print(f"[!] WiFi scan error: {e}")
        
        return networks
    
    def _parse_wifi_csv(self, filename: str) -> List[WiFiNetwork]:
        """Parse airodump-ng CSV output"""
        networks = []
        
        try:
            with open(filename, 'r') as f:
                lines = f.readlines()
            
            timestamp = datetime.now().isoformat()
            parsing_networks = False
            
            for line in lines:
                line = line.strip()
                
                if line.startswith('BSSID'):
                    parsing_networks = True
                    continue
                if line.startswith('Station MAC'):
                    parsing_networks = False
                    continue
                
                if parsing_networks and ',' in line:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        try:
                            bssid = parts[0]
                            signal = int(parts[8]) if parts[8].lstrip('-').isdigit() else -100
                            
                            network = WiFiNetwork(
                                bssid=bssid,
                                ssid=parts[13],
                                channel=int(parts[3]) if parts[3].isdigit() else 0,
                                encryption=parts[5],
                                cipher=parts[6],
                                authentication=parts[7],
                                signal_dbm=signal,
                                signal_quality=self._dbm_to_quality(signal),
                                clients=[],
                                manufacturer=self.get_manufacturer(bssid),
                                first_seen=parts[1],
                                last_seen=parts[2]
                            )
                            networks.append(network)
                            self.wifi_networks[bssid] = network
                        except Exception as e:
                            pass
        except Exception as e:
            print(f"[!] Error parsing WiFi data: {e}")
        
        return networks
    
    def _dbm_to_quality(self, dbm: int) -> str:
        """Convert signal dBm to quality rating"""
        if dbm > -50:
            return "Excellent"
        elif dbm > -60:
            return "Good"
        elif dbm > -70:
            return "Fair"
        else:
            return "Poor"
    
    def generate_network_map(self) -> Dict:
        """Generate comprehensive network map"""
        return {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'mapper_version': '1.0.0',
                'total_devices': len(self.devices),
                'total_wifi_networks': len(self.wifi_networks),
            },
            'ethernet_devices': [
                asdict(d) for d in self.devices.values()
            ],
            'wifi_networks': [
                asdict(n) for n in self.wifi_networks.values()
            ],
            'statistics': {
                'device_types': self._count_device_types(),
                'wifi_security': self._wifi_security_stats(),
                'network_segments': self._get_network_segments(),
            }
        }
    
    def _count_device_types(self) -> Dict[str, int]:
        """Count devices by type"""
        counts = {}
        for device in self.devices.values():
            counts[device.device_type] = counts.get(device.device_type, 0) + 1
        return counts
    
    def _wifi_security_stats(self) -> Dict[str, int]:
        """Get WiFi security statistics"""
        stats = {'Open': 0, 'WEP': 0, 'WPA': 0, 'WPA2': 0, 'WPA3': 0, 'Unknown': 0}
        
        for network in self.wifi_networks.values():
            enc = network.encryption.upper()
            if 'OPN' in enc:
                stats['Open'] += 1
            elif 'WEP' in enc:
                stats['WEP'] += 1
            elif 'WPA3' in enc:
                stats['WPA3'] += 1
            elif 'WPA2' in enc:
                stats['WPA2'] += 1
            elif 'WPA' in enc:
                stats['WPA'] += 1
            else:
                stats['Unknown'] += 1
        
        return stats
    
    def _get_network_segments(self) -> List[str]:
        """Get unique network segments"""
        segments = set()
        for device in self.devices.values():
            if device.ip:
                parts = device.ip.split('.')
                if len(parts) == 4:
                    segments.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
        return sorted(list(segments))
    
    def save_map(self, filename: str = None):
        """Save network map to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"network_map_{timestamp}.json"
        
        network_map = self.generate_network_map()
        
        with open(filename, 'w') as f:
            json.dump(network_map, f, indent=2)
        
        print(f"[+] Network map saved to: {filename}")
        return filename
    
    def print_summary(self):
        """Print formatted network summary"""
        print("\n" + "="*60)
        print("NETWORK MAPPING SUMMARY")
        print("="*60)
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Ethernet Devices: {len(self.devices)}")
        print(f"WiFi Networks: {len(self.wifi_networks)}")
        
        if self.devices:
            print("\n--- Ethernet Devices ---")
            for device in self.devices.values():
                print(f"  {device.ip or 'N/A':<15} {device.mac:<18} {device.manufacturer:<20} {device.device_type}")
        
        if self.wifi_networks:
            print("\n--- WiFi Networks ---")
            for network in self.wifi_networks.values():
                print(f"  {network.ssid or 'Hidden':<20} {network.bssid:<18} {network.encryption:<10} {network.signal_quality}")
        
        print("="*60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description='Network Mapper - WiFi and Ethernet discovery'
    )
    parser.add_argument(
        '--ethernet', '-e',
        action='store_true',
        help='Scan Ethernet network (ARP-based)'
    )
    parser.add_argument(
        '--wifi', '-w',
        metavar='INTERFACE',
        help='WiFi interface to scan (e.g., wlan0)'
    )
    parser.add_argument(
        '--duration', '-d',
        type=int,
        default=30,
        help='WiFi scan duration in seconds (default: 30)'
    )
    parser.add_argument(
        '--network', '-n',
        default='192.168.1.0/24',
        help='Network CIDR to scan (default: 192.168.1.0/24)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output JSON file'
    )
    parser.add_argument(
        '--port-scan',
        action='store_true',
        help='Scan common ports on discovered hosts'
    )
    
    args = parser.parse_args()
    
    mapper = NetworkMapper()
    
    # If no options specified, do Ethernet scan
    if not args.ethernet and not args.wifi:
        args.ethernet = True
    
    if args.ethernet:
        devices = mapper.discover_ethernet_devices(args.network)
        print(f"[+] Found {len(devices)} Ethernet devices")
        
        if args.port_scan:
            print("[*] Scanning common ports...")
            for device in devices:
                if device.ip:
                    print(f"  Scanning {device.ip}...", end=' ', flush=True)
                    device.open_ports = mapper.scan_ports(device.ip)
                    device.services = [mapper.get_service_name(p) for p in device.open_ports]
                    print(f"{len(device.open_ports)} open")
    
    if args.wifi:
        networks = mapper.scan_wifi_networks(args.wifi, args.duration)
        print(f"[+] Found {len(networks)} WiFi networks")
    
    # Print summary
    mapper.print_summary()
    
    # Save to file
    output_file = mapper.save_map(args.output)
    
    print(f"[*] Complete! Map saved to: {output_file}")


if __name__ == '__main__':
    main()
