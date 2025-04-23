#!/usr/bin/env python3
import nmap
import json
import os

CRITICAL_CVES = {
    "ms17-010": {
        "name": "EternalBlue",
        "port": 445,
        "service": "microsoft-ds",
        "cve": "CVE-2017-0144",
        "cvss": 10.0,
        "nmap_script": "smb-vuln-ms17-010",
        "description": "Remote code execution via SMB (used by WannaCry ransomware)."
    },
    "cve-2019-0708": {
        "name": "BlueKeep",
        "port": 3389,
        "service": "ms-wbt-server",
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "nmap_script": "rdp-vuln-ms12-020",
        "description": "RCE in Windows RDP (wormable)."
    },
    "cve-2021-44228": {
        "name": "Log4Shell",
        "port": [80, 443, 8080],
        "service": "http",
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "nmap_script": "http-vuln-log4shell",
        "description": "RCE in Apache Log4j (cloud/server exploit)."
    },
    "cve-2014-0160": {
        "name": "Heartbleed",
        "port": 443,
        "service": "ssl/https",
        "cve": "CVE-2014-0160",
        "cvss": 9.8,
        "nmap_script": "ssl-heartbleed",
        "description": "Leaks sensitive data from TLS/SSL servers."
    }
}

def scan_ports(ip):
    print(f"[*] Scanning {ip} for open ports and critical CVEs...")
    nm = nmap.PortScanner()
    nmap_scripts = ' '.join([v['nmap_script'] for v in CRITICAL_CVES.values()])
    nm.scan(ip, arguments=f"-sV --script {nmap_scripts} --open")
    if ip not in nm.all_hosts():
        print(f"[!] Host {ip} is down or not responding.")
        return None
    return nm

def check_cves(nm, ip):
    potential_vulns = []
    critical_vulns = []
    confirmed_ports = set()  # Track ports with confirmed vulnerabilities

    for cve_id, cve_data in CRITICAL_CVES.items():
        ports = [cve_data["port"]] if isinstance(cve_data["port"], int) else cve_data["port"]
        for port in ports:
            if port in nm[ip]['tcp']:
                script_output = nm[ip]['tcp'][port].get('script', {}).get(cve_data["nmap_script"], "")
                
                if "VULNERABLE" in script_output:
                    critical_vulns.append({
                        "cve": cve_data["cve"],
                        "name": cve_data["name"],
                        "port": port,
                        "service": cve_data["service"],
                        "description": cve_data["description"],
                        "cvss": cve_data["cvss"],
                        "status": "CONFIRMED"
                    })
                    confirmed_ports.add(port)  # Mark this port as confirmed
                elif port not in confirmed_ports:
                    potential_vulns.append({
                        "cve": cve_data["cve"],
                        "name": cve_data["name"],
                        "port": port,
                        "service": cve_data["service"],
                        "description": cve_data["description"],
                        "cvss": cve_data["cvss"]
                    })
    
    return potential_vulns, critical_vulns
def print_banner():
    # Add your ASCII art banner here
    banner = """

░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓███████▓▒░ ░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░ ░▒▓███████▓▒░  
  ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
  ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓██▓▒░   ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 

    With great power, comes great responsibility. Please do not perform scans on networks you do not own, or are not authorized to test on.
    Michael Awad and Intellipy are not responsible or liable for any damage that a would-be attacker may cause in utilizing the suite or the software therein. 
    Vulnerability Scanner v1.1
    """
    print(banner)

def main():
    print_banner()
    target_ip = input("Enter target IP: ").strip()
    hostname = input("Enter hostname (e.g., WIN-LAPTOP): ").strip()
    output_file = f"./reports/{hostname}_Report.txt"

    nm = scan_ports(target_ip)
    if not nm:
        return

    # Print active services (terminal)
    print("\n[+] Active Services:")
    for port, data in nm[target_ip]['tcp'].items():
        service = data['name']
        version = data.get('version', 'unknown')
        print(f"  - {service} {version} (Port {port})")

    potential_vulns, critical_vulns = check_cves(nm, target_ip)
    results = {
        "target_ip": target_ip,
        "hostname": hostname,
        "active_services": {port: {"service": data['name'], "version": data.get('version', 'unknown')} 
                          for port, data in nm[target_ip]['tcp'].items()},
        "potential_vulnerabilities": potential_vulns if potential_vulns else "None (open ports checked)",
        "critical_vulnerabilities": critical_vulns if critical_vulns else "None (no exploits confirmed)"
    }

    os.makedirs("./reports", exist_ok=True)
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Report saved to {output_file}")

if __name__ == "__main__":
    main()
