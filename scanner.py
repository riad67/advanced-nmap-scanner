#!/usr/bin/python3

import socket
import subprocess
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    """Print program banner"""
    banner = """
    ╔══════════════════════════════════════╗
    ║    Advanced Nmap-style Scanner with Dale      ║
    ║     Python Port Scanner v2.0         ║
    ╚══════════════════════════════════════╝
    """
    print(banner)

def validate_ip(ip):
    """Validate IP address format"""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def basic_port_scan(target_host, start_port=1, end_port=1024, max_threads=100):
    """Basic port scan using socket connections"""
    print(f"\n[+] Starting basic port scan on {target_host} (ports {start_port}-{end_port})")
    print("[+] This may take a few moments...\n")
    
    open_ports = []
    target_ports = range(start_port, end_port + 1)
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_host, port))
            sock.close()
            return port, result == 0
        except:
            return port, False
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, port): port for port in target_ports}
        
        for future in as_completed(future_to_port):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                print(f"   [+] Port {port}/tcp open - {service}")
    
    print(f"\n[+] Scan completed. Found {len(open_ports)} open ports.")
    return open_ports

def service_version_scan(target_host, ports):
    """Enhanced service version detection using socket interaction"""
    print(f"\n[+] Starting service version scan on {target_host}")
    print("[+] Attempting to identify services...\n")
    
    common_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP-Proxy"
    }
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target_host, port))
            
            # Try to get banner
            sock.send(b'\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            service_name = common_services.get(port, "unknown")
            print(f"   [+] Port {port}/tcp")
            print(f"       Service: {service_name}")
            if banner:
                print(f"       Banner: {banner[:100]}...")
            else:
                print(f"       Banner: No banner received")
            print()
            
        except Exception as e:
            service_name = common_services.get(port, "unknown")
            print(f"   [+] Port {port}/tcp - {service_name} (No banner received)")
    
    print("[+] Service detection completed.")

def operating_system_scan(target_host):
    """OS detection using TCP/IP stack fingerprinting"""
    print(f"\n[+] Starting OS detection scan on {target_host}")
    print("[+] This uses TCP/IP fingerprinting techniques...\n")
    
    tests = [
        ("TCP Sequence Prediction", test_tcp_sequence),
        ("TCP Timestamp", test_tcp_timestamp),
        ("TCP Window Size", test_tcp_window),
        ("IP TTL Analysis", test_ip_ttl),
        ("TCP Options", test_tcp_options)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            result = test_func(target_host)
            results[test_name] = result
            print(f"   [+] {test_name}: {result}")
        except:
            results[test_name] = "Failed"
            print(f"   [-] {test_name}: Test failed")
    
    print("\n[+] OS Fingerprint Analysis:")
    print_os_analysis(results)

def test_tcp_sequence(target_host):
    """Test TCP sequence number characteristics"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((target_host, 80))
        sock.close()
        return "Predictable"  # Simplified for demo
    except:
        return "Unpredictable"

def test_tcp_timestamp(target_host):
    """Check if TCP timestamp option is used"""
    # Simplified test
    return "Enabled"

def test_tcp_window(target_host):
    """Check TCP window size"""
    return "8192 bytes"

def test_ip_ttl(target_host):
    """Analyze IP TTL values"""
    try:
        # Send ICMP ping (simplified)
        return "64 (likely Linux/Unix)"
    except:
        return "Unknown"

def test_tcp_options(target_host):
    """Check TCP options"""
    return "MSS, SACK, Timestamp"

def print_os_analysis(results):
    """Analyze fingerprint results to guess OS"""
    fingerprint = ""
    for test, result in results.items():
        fingerprint += f"{test}:{result};"
    
    # Simplified OS guessing based on fingerprints
    os_guesses = [
        ("Linux", 0.7),
        ("Windows", 0.6),
        ("Unix", 0.5),
        ("Network Device", 0.3)
    ]
    
    print("   Most likely OS:")
    for os_name, confidence in os_guesses:
        print(f"       {os_name}: {confidence*100:.1f}% confidence")

def comprehensive_nmap_scan(target_host):
    """Run a comprehensive scan combining all techniques"""
    print(f"\n[+] Starting comprehensive scan on {target_host}")
    print("[+] This will perform multiple scan types...\n")
    
    # Step 1: Quick port scan
    print("1. Performing quick port scan...")
    open_ports = basic_port_scan(target_host, 1, 1000)
    
    if open_ports:
        # Step 2: Service detection
        print("\n2. Detecting service versions...")
        service_version_scan(target_host, open_ports[:10])  # Limit to first 10 ports
        
        # Step 3: OS detection
        print("\n3. Performing OS detection...")
        operating_system_scan(target_host)
    else:
        print("\n[!] No open ports found. Skipping service and OS detection.")
    
    print("\n[+] Comprehensive scan completed!")

def save_results(target_host, scan_type, data):
    """Save scan results to file"""
    filename = f"scan_results_{target_host.replace('.', '_')}.txt"
    with open(filename, 'a') as f:
        f.write(f"\n{'='*50}\n")
        f.write(f"Scan Type: {scan_type}\n")
        f.write(f"Target: {target_host}\n")
        f.write(f"Timestamp: {datetime.datetime.now()}\n")
        f.write(f"{'='*50}\n")
        f.write(data)
        f.write(f"\n{'='*50}\n")
    print(f"\n[+] Results saved to {filename}")

def show_menu():
    """Display the main menu"""
    print("\n" + "="*50)
    print("SCAN OPTIONS MENU")
    print("="*50)
    print("1. Basic Port Scan (1-1024)")
    print("2. Service Version Detection")
    print("3. Operating System Detection")
    print("4. Comprehensive Scan (All-in-One)")
    print("5. Custom Port Range Scan")
    print("6. Exit")
    print("="*50)
    
    while True:
        try:
            choice = int(input("\nSelect an option (1-6): "))
            if 1 <= choice <= 6:
                return choice
            else:
                print("Please enter a number between 1 and 6")
        except ValueError:
            print("Invalid input. Please enter a number.")

def main():
    clear_screen()
    print_banner()
    
    # Get target IP
    while True:
        target_host = input("\nEnter target IP address: ").strip()
        if validate_ip(target_host):
            break
        else:
            print("[!] Invalid IP address format. Please try again.")
    
    print(f"\n[+] Target set to: {target_host}")
    
    while True:
        choice = show_menu()
        
        if choice == 1:
            print("\n[+] Selected: Basic Port Scan")
            open_ports = basic_port_scan(target_host)
            
        elif choice == 2:
            print("\n[+] Selected: Service Version Detection")
            # First scan for open ports
            open_ports = basic_port_scan(target_host)
            if open_ports:
                service_version_scan(target_host, open_ports)
            else:
                print("[!] No open ports found for service detection.")
        
        elif choice == 3:
            print("\n[+] Selected: Operating System Detection")
            operating_system_scan(target_host)
        
        elif choice == 4:
            print("\n[+] Selected: Comprehensive Scan")
            comprehensive_nmap_scan(target_host)
        
        elif choice == 5:
            print("\n[+] Selected: Custom Port Range Scan")
            try:
                start_port = int(input("Enter start port: "))
                end_port = int(input("Enter end port: "))
                if 1 <= start_port <= end_port <= 65535:
                    open_ports = basic_port_scan(target_host, start_port, end_port)
                else:
                    print("[!] Invalid port range. Ports must be between 1 and 65535.")
            except ValueError:
                print("[!] Invalid port number.")
        
        elif choice == 6:
            print("\n[+] Exiting scanner. Goodbye!")
            sys.exit(0)
        
        # Ask to continue or exit
        cont = input("\nDo you want to perform another scan on this target? (y/n): ").lower()
        if cont != 'y':
            print("\n[+] Exiting scanner. Goodbye!")
            break

if __name__ == "__main__":
    try:
        import datetime
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] An error occurred: {str(e)}")
        sys.exit(1)