#!/usr/bin/env python3
import os
import sys
import re
import time
import subprocess
from pyvis.network import Network

# Configuration - EXACTLY AS IN YOUR ORIGINAL
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
REPORTS_DIR = os.path.join(SCRIPT_DIR, "reports")
SCAN_MODES = {
    '1': {'name': 'Normal', 'desc': 'ARP + NetBIOS scan'},
    '2': {'name': 'Advanced', 'desc': '+ OS detection (ARP → NBTScan → Nmap)'},
    '3': {'name': 'Stealth', 'desc': 'Slower, less detectable'}
}

# UPDATED ICON CONFIGURATION - ONLY CHANGES MADE
ICON_CONFIG = {
    'windows': {'shape': 'image', 'image': 'https://cdn.jsdelivr.net/npm/simple-icons@v5/icons/windows.svg', 'size': 20},
    'linux': {'shape': 'image', 'image': 'https://cdn.jsdelivr.net/npm/simple-icons@v5/icons/linux.svg', 'size': 20},
    'android': {'shape': 'image', 'image': 'https://cdn.jsdelivr.net/npm/simple-icons@v5/icons/android.svg', 'size': 20},
    'apple': {'shape': 'image', 'image': 'https://cdn.jsdelivr.net/npm/simple-icons@v5/icons/apple.svg', 'size': 20},
    'router': {'shape': 'image', 'image': 'https://cdn.jsdelivr.net/npm/simple-icons@v5/icons/router.svg', 'size': 20},
    'unknown': {'shape': 'image', 'image': 'https://cdn.jsdelivr.net/npm/simple-icons@v5/icons/question.svg', 'size': 20}
}

def show_banner():
    print("""
░▒▓███████▓▒░░▒▓██████████████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 

    """)

def setup_environment():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    print(f"[*] Reports will be saved to: {REPORTS_DIR}")

def get_user_input():
    print("\n[+] Available Scan Modes:")
    for mode, info in SCAN_MODES.items():
        print(f"    {mode}. {info['name']}: {info['desc']}")
    
    while True:
        mode = input("\nSelect mode (1-3): ").strip()
        if mode in SCAN_MODES:
            break
        print("[!] Invalid selection. Try again.")
    
    ip_range = input("IP range to scan (e.g., 172.16.2.0/24): ").strip()
    interface = input("Network interface (e.g., eth0): ").strip()
    output_file = input(f"Output filename (default: {SCAN_MODES[mode]['name'].lower()}_scan.html): ").strip()
    output_file = output_file or f"{SCAN_MODES[mode]['name'].lower()}_scan.html"
    
    return mode, ip_range, interface, output_file

def run_command(cmd, description):
    print(f"\n[+] {description}...")
    print(f"    Command: {cmd}")
    
    process = subprocess.Popen(
        cmd, 
        shell=True, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, 
        text=True
    )
    
    output_buffer = []
    while True:
        output = process.stdout.readline()
        if output == '' and process.poll() is not None:
            break
        if output:
            print("   ", output.strip())
            output_buffer.append(output)
    
    return ''.join(output_buffer)

def get_arp_table():
    cmd = "arp -a"
    output = run_command(cmd, "Getting complete ARP table")
    devices = []
    
    for line in output.splitlines():
        if match := re.match(r".*\((\d+\.\d+\.\d+\.\d+)\).*", line):
            ip = match.group(1)
            mac = re.search(r"(([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2}))", line)
            if mac:
                devices.append({
                    'ip': ip,
                    'mac': mac.group(0),
                    'type': 'unknown'
                })
    return devices

def get_nbtscan_info(ip_range):
    cmd = f"nbtscan -r {ip_range}"
    output = run_command(cmd, "Running NBTScan")
    hostnames = {}
    
    for line in output.splitlines():
        if re.match(r"\d+\.\d+\.\d+\.\d+", line):
            parts = line.split()
            ip = parts[0]
            name = parts[1] if len(parts) > 1 else "Unknown"
            hostnames[ip] = name
    return hostnames

def get_nmap_os(ip):
    cmd = f"sudo nmap -O --osscan-guess {ip}"
    output = run_command(cmd, f"Running OS detection on {ip}")
    
    os_info = "Unknown"
    if "Running:" in output:
        os_info = output.split("Running:")[1].split("\n")[0].strip()
    elif "Aggressive OS guesses:" in output:
        os_info = output.split("Aggressive OS guesses:")[1].split("\n")[0].strip()
        os_info = os_info.split(",")[0].strip()
    
    return os_info

def determine_icon(ip, os_info):
    os_info = str(os_info).lower()
    
    # Force question mark for Unknown or empty OS
    if 'unknown' in os_info or not os_info.strip():
        return ICON_CONFIG['unknown']
    
    # Force question mark for Crestron
    if 'crestron' in os_info:
        return ICON_CONFIG['unknown']
    
    # Router detection
    if ip.endswith('.1') or ip.endswith('.254'):
        return ICON_CONFIG['router']
    
    # Android detection (must come before Linux)
    if 'android' in os_info:
        return ICON_CONFIG['android']
    
    # Other OS detection
    if 'windows' in os_info:
        return ICON_CONFIG['windows']
    elif 'linux' in os_info:
        return ICON_CONFIG['linux']
    elif 'mac' in os_info or 'apple' in os_info or 'ios' in os_info:
        return ICON_CONFIG['apple']
    
    # Default to question mark
    return ICON_CONFIG['unknown']

def scan_network(mode, ip_range, interface):
    print(f"\n[=== {SCAN_MODES[mode]['name']} MODE SCAN ===]")
    
    devices = get_arp_table()
    if not devices:
        print("[-] No devices found in ARP table")
        return []
    
    print("\n[+] Running NBTScan for hostname identification...")
    hostnames = get_nbtscan_info(ip_range)
    
    if mode == '2':
        print("\n[+] Running OS detection on all hosts...")
        for device in devices:
            ip = device['ip']
            if ip in hostnames and hostnames[ip] != "Unknown":
                device['hostname'] = hostnames[ip]
                device['os'] = "Windows"
            else:
                device['os'] = get_nmap_os(ip)
            print(f"    {ip}: {device.get('os', 'Unknown')}")
    
    for device in devices:
        if device['ip'] in hostnames:
            device['hostname'] = hostnames[device['ip']]
    
    unique_devices = {}
    for device in devices:
        unique_devices[device['ip']] = device
    return list(unique_devices.values())

def generate_report(devices, mode, output_path):
    net = Network(
        height="800px",
        width="100%",
        bgcolor="#222222",
        font_color="white",
        notebook=False
    )
    
    net.set_options("""
    {
      "nodes": {
        "font": {"size": 12},
        "scaling": {"min": 20, "max": 25}
      },
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -30,
          "centralGravity": 0.01,
          "springLength": 150,
          "springConstant": 0.03
        },
        "minVelocity": 0.75,
        "solver": "forceAtlas2Based"
      }
    }
    """)
    
    for device in devices:
        os_info = device.get('os', 'Unknown')
        icon_props = determine_icon(device['ip'], os_info)
        
        net.add_node(
            device["ip"],
            label=f"{device['ip']}\n{os_info if mode == '2' else device.get('hostname', '')}",
            title=f"IP: {device['ip']}\nMAC: {device.get('mac', 'Unknown')}\nOS: {os_info}",
            **icon_props,
            color="#00aaff" if device.get('hostname', 'Unknown') != "Unknown" else "#ff9900"
        )
    
    if len(devices) > 1:
        router_ip = min(device['ip'] for device in devices)
        for device in devices:
            if device['ip'] != router_ip:
                net.add_edge(router_ip, device['ip'])
    
    html = net.generate_html()
    html = html.replace('<head>', '''<head>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0/css/all.min.css">
    <style>
      #mynetwork {
        width: 100%!important;
        height: 800px!important;
      }
    </style>
    ''')
    
    with open(output_path, 'w') as f:
        f.write(html)

def main():
    show_banner()
    setup_environment()
    
    try:
        mode, ip_range, interface, output_file = get_user_input()
        output_path = os.path.join(REPORTS_DIR, output_file)
        
        devices = scan_network(mode, ip_range, interface)
        if not devices:
            print("\n[-] No devices found. Check network settings.")
            return
        
        generate_report(devices, mode, output_path)
        print(f"\n[+] Report generated: {output_path}")
        print(f"    To view: firefox {output_path}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
