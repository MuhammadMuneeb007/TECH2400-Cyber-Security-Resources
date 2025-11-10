import subprocess
import platform
import re
import socket
from typing import List, Dict

def get_local_ip():
    """Get the local IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def get_network_range():
    """Calculate network range from local IP."""
    local_ip = get_local_ip()
    ip_parts = local_ip.split('.')
    network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    return network

def is_valid_device(ip: str, mac: str) -> bool:
    """Filter out broadcast, multicast, and invalid addresses."""
    # Filter broadcast addresses
    if mac.lower().replace('-', '') == 'ffffffffffff':
        return False
    
    # Filter multicast addresses (224.0.0.0 - 239.255.255.255)
    ip_parts = ip.split('.')
    if len(ip_parts) == 4:
        first_octet = int(ip_parts[0])
        if 224 <= first_octet <= 239:
            return False
        
        # Filter broadcast addresses ending in .255
        if ip_parts[3] == '255':
            return False
    
    # Filter multicast MAC addresses (starting with 01-00-5e)
    if mac.lower().startswith('01-00-5e') or mac.lower().startswith('01:00:5e'):
        return False
    
    return True

def resolve_hostname(ip: str) -> str:
    """Try to resolve hostname from IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return 'Unknown'

def scan_with_nmap(network_range: str) -> List[Dict]:
    """Scan network using nmap."""
    print(f"\n[*] Scanning network {network_range} with nmap...")
    devices = []
    
    try:
        # Run nmap with ping scan and OS detection
        result = subprocess.run(
            ['nmap', '-sn', network_range],
            capture_output=True,
            text=True,
            timeout=120
        )
        
        # Parse nmap output
        lines = result.stdout.split('\n')
        current_device = {}
        
        for line in lines:
            if 'Nmap scan report for' in line:
                if current_device:
                    devices.append(current_device)
                current_device = {}
                
                # Extract hostname and IP
                match = re.search(r'for (.+?) \((.+?)\)', line)
                if match:
                    current_device['hostname'] = match.group(1)
                    current_device['ip'] = match.group(2)
                else:
                    match = re.search(r'for (.+)$', line)
                    if match:
                        current_device['ip'] = match.group(1).strip()
                        current_device['hostname'] = 'Unknown'
            
            elif 'MAC Address:' in line:
                match = re.search(r'MAC Address: (.+?) \((.+?)\)', line)
                if match:
                    current_device['mac'] = match.group(1)
                    current_device['vendor'] = match.group(2)
        
        if current_device:
            devices.append(current_device)
            
    except FileNotFoundError:
        print("[!] nmap not found. Please install nmap.")
    except subprocess.TimeoutExpired:
        print("[!] nmap scan timed out.")
    except Exception as e:
        print(f"[!] Error during nmap scan: {e}")
    
    return devices

def scan_with_arp(network_range: str) -> List[Dict]:
    """Scan network using ARP (Windows/Linux)."""
    print(f"\n[*] Scanning network with ARP...")
    devices = []
    seen_ips = set()
    
    try:
        system = platform.system()
        
        if system == "Windows":
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    
                    # Skip invalid devices and duplicates
                    if not is_valid_device(ip, mac) or ip in seen_ips:
                        continue
                    
                    seen_ips.add(ip)
                    hostname = resolve_hostname(ip)
                    devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})
        
        else:  # Linux/Mac
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            for line in lines:
                match = re.search(r'(\d+\.\d+\.\d+\.\d+).*?([0-9a-fA-F:]+)', line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2)
                    
                    # Skip invalid devices and duplicates
                    if not is_valid_device(ip, mac) or ip in seen_ips:
                        continue
                    
                    seen_ips.add(ip)
                    hostname = resolve_hostname(ip)
                    devices.append({'ip': ip, 'mac': mac, 'hostname': hostname})
    
    except Exception as e:
        print(f"[!] Error during ARP scan: {e}")
    
    return devices

def display_devices(devices: List[Dict]):
    """Display discovered devices in a formatted table."""
    if not devices:
        print("\n[!] No devices found.")
        return
    
    # Sort devices by IP address
    devices_sorted = sorted(devices, key=lambda x: [int(i) for i in x.get('ip', '0.0.0.0').split('.')])
    
    print(f"\n[+] Found {len(devices_sorted)} device(s):\n")
    print("-" * 90)
    print(f"{'IP Address':<18} {'MAC Address':<20} {'Hostname':<30} {'Vendor'}")
    print("-" * 90)
    
    for device in devices_sorted:
        ip = device.get('ip', 'N/A')
        mac = device.get('mac', 'N/A')
        hostname = device.get('hostname', 'Unknown')
        vendor = device.get('vendor', 'N/A')
        
        # Truncate long hostnames
        if len(hostname) > 28:
            hostname = hostname[:25] + '...'
        
        print(f"{ip:<18} {mac:<20} {hostname:<30} {vendor}")
    
    print("-" * 90)
    
    # Display device type summary
    gateway_count = sum(1 for d in devices_sorted if d.get('ip', '').endswith('.1'))
    print(f"\n[i] Potential gateway devices: {gateway_count}")

def main():
    """Main function to run network scanner."""
    print("=" * 80)
    print("Network Device Scanner")
    print("=" * 80)
    
    local_ip = get_local_ip()
    network_range = get_network_range()
    
    print(f"\n[*] Local IP: {local_ip}")
    print(f"[*] Network Range: {network_range}")
    
    # Try nmap first
    devices = scan_with_nmap(network_range)
    
    # If nmap fails or returns no results, try ARP
    if not devices:
        print("\n[*] Trying ARP scan as fallback...")
        devices = scan_with_arp(network_range)
    
    # Display results
    display_devices(devices)
    
    print("\n[*] Scan complete!")

if __name__ == "__main__":
    main()
