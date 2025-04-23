#!/usr/bin/env python3
import socket
import paramiko
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

# Default credentials (loaded from creds.txt if available)
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("root", "password"),
    ("user", "user"),
    ("guest", "guest")
]

def load_credentials():
    """Load credentials from creds.txt if available"""
    try:
        with open("creds.txt", "r") as f:
            return [tuple(line.strip().split(":", 1)) for line in f 
                   if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return DEFAULT_CREDS

def test_ssh(host, port, username, password, timeout=5):
    """Test SSH credentials"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=username,
                   password=password, timeout=timeout, banner_timeout=30)
        ssh.close()
        return True
    except:
        return False

def test_telnet(host, port, username, password, timeout=5):
    """Test Telnet credentials"""
    try:
        tn = socket.create_connection((host, port), timeout=timeout)
        
        # Read initial banner
        banner = tn.recv(1024)
        
        # Send credentials (basic Telnet auth pattern)
        tn.send(username.encode() + b"\r\n")
        tn.recv(1024)  # Wait for password prompt
        tn.send(password.encode() + b"\r\n")
        
        # Check response for success indicators
        response = tn.recv(1024)
        tn.close()
        
        return b"Login incorrect" not in response and b"Welcome" in response
    except:
        return False

def scan_target(target, port, protocol):
    """Test all credentials against a target"""
    credentials = load_credentials()
    print(f"\n[*] Testing {protocol.upper()} on {target}:{port}")
    
    for username, password in credentials:
        if protocol == "ssh":
            success = test_ssh(target, port, username, password)
        else:
            success = test_telnet(target, port, username, password)
        
        if success:
            print(f"[+] {protocol.upper()} Success: {target}:{port} - {username}:{password}")
            with open("found_credentials.txt", "a") as f:
                f.write(f"{protocol.upper()}:{target}:{port}:{username}:{password}\n")
            return True
    
    print(f"[-] No valid {protocol} credentials found")
    return False
def print_banner():
    # Add your ASCII art banner here
    banner = """



 ░▒▓███████▓▒░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░                                                     
░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░                                                     
░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░                                                     
 ░▒▓██████▓▒░░▒▓██████▓▒░░▒▓████████▓▒░                                                     
       ░▒▓█▓▒░     ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░                                                     
       ░▒▓█▓▒░     ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░                                                     
░▒▓███████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░                                                     


 ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░                                        
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░                                       
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░                                       
░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓█▓▒░░▒▓█▓▒░                                       
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░                                       
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░                                       
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░                                        


 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓████████▓▒░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░     ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 



    With great power, comes great responsibility. Please do not perform scans on networks you do not own, or are not authorized to test on.
    Michael Awad and Intellipy are not responsible or liable for any damage that a would-be attacker may cause in utilizing the suite or the software therein. 
    Vulnerability Scanner v1.1
    """
    print(banner)

def menu():
    print_banner()
    """Display interactive menu"""
    print("\n" + "="*40)
    print("Telnet/SSH Credential Scanner")
    print("="*40)
    print("1. Scan single IP/hostname")
    print("2. Scan from targets file")
    print("3. Change ports (current: SSH=22, Telnet=23)")
    print("4. Exit")
    
    return input("\nSelect option: ").strip()

def main():
    ssh_port = 22
    telnet_port = 23
    
    while True:
        choice = menu()
        
        if choice == "1":
            target = input("Enter IP/hostname: ").strip()
            scan_target(target, ssh_port, "ssh")
            scan_target(target, telnet_port, "telnet")
            
        elif choice == "2":
            filepath = input("Enter path to targets file: ").strip()
            try:
                with open(filepath) as f:
                    targets = [line.strip() for line in f if line.strip()]
                
                with ThreadPoolExecutor(max_workers=10) as executor:
                    for target in targets:
                        executor.submit(scan_target, target, ssh_port, "ssh")
                        executor.submit(scan_target, target, telnet_port, "telnet")
            except FileNotFoundError:
                print("[!] File not found")
                
        elif choice == "3":
            try:
                ssh_port = int(input("New SSH port: ").strip())
                telnet_port = int(input("New Telnet port: ").strip())
                print(f"Ports updated (SSH={ssh_port}, Telnet={telnet_port})")
            except ValueError:
                print("[!] Invalid port number")
                
        elif choice == "4":
            print("Exiting...")
            break
            
        else:
            print("[!] Invalid option")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
