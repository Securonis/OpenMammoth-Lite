#!/usr/bin/env python3
# OpenMammoth-Lite - Simple Network Security Tool

from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import time, os, threading, atexit, signal
import subprocess
import argparse
import re
import datetime
import platform

# Colors for terminal output
COLORS = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
    'white': '\033[97m',
    'reset': '\033[0m'
}

# Attack detection counters and settings
syn_counts = defaultdict(lambda: [0, time.time(), []])
connection_attempts = defaultdict(lambda: [set(), time.time(), {}])
icmp_flood_counts = defaultdict(lambda: [0, time.time()])
udp_flood_counts = defaultdict(lambda: [0, time.time(), 0])  # [count, last_time, total_bytes]
http_flood_counts = defaultdict(lambda: [0, time.time(), set()])  # [count, last_time, user_agents]
authentication_failures = defaultdict(lambda: [0, time.time()])

# Advanced attack detection counters
dns_amp_counts = defaultdict(lambda: [0, time.time(), 0])  # [count, last_time, total_bytes]
arp_spoofing_attempts = defaultdict(lambda: [set(), time.time()])  # [claimed_macs, last_time]
ssl_attacks = defaultdict(lambda: [0, time.time(), set()])  # [count, last_time, ssl_versions]
brute_force_attempts = defaultdict(lambda: [{}, time.time()])  # [user_attempts, last_time]

# Global settings
blocklist = set()
BLOCK_THRESHOLD = 100         # SYN floods
PORT_SCAN_THRESHOLD = 20      # Port scans
ICMP_FLOOD_THRESHOLD = 50     # ICMP/ping floods
UDP_FLOOD_THRESHOLD = 100     # UDP floods
HTTP_FLOOD_THRESHOLD = 50     # HTTP floods (same IP, port 80/443)
AUTH_FAILURE_THRESHOLD = 5    # Authentication failures
DNS_AMP_THRESHOLD = 15       # DNS amplification attacks
ARPSPOOF_MAC_THRESHOLD = 2   # ARP spoofing (multiple MACs for same IP)
SSL_SCAN_THRESHOLD = 5       # SSL scans or downgrade attempts
BRUTE_FORCE_THRESHOLD = 10   # Brute force login attempts
TIME_WINDOW = 60             # Time window for rate-based detection (seconds)
FINSCAN_THRESHOLD = 10       # FIN scan detection
XMAS_THRESHOLD = 8           # XMAS scan detection
NULLSCAN_THRESHOLD = 8       # NULL scan detection
BLOCK_COMMAND = "iptables -I INPUT -s {} -j DROP"
IP_TIMEOUT = 300  # seconds
BLOCKLIST_FILE = "/var/log/openmammoth_lite.blocklist"
LOG_FILE = "/var/log/openmammoth_lite.log"

# Global monitoring state
monitoring_active = False
detection_running = False
whitelist = set(['127.0.0.1', '192.168.1.1'])  # Default whitelist
selected_interface = None  # Selected network interface
program_start_time = time.time()  # Program start time

def detect_tor_connection():
    """Detect if Tor is running on the system"""
    try:
        output = subprocess.check_output(["netstat", "-tunlp"]).decode()
        if ":9050" in output or ":9150" in output:
            print(f"{COLORS['yellow']}[!] Tor network detected! This may conflict with iptables rules.{COLORS['reset']}")
            return True
    except Exception:
        pass
    return False


def log_message(message, level="INFO"):
    """Log a message to the log file"""
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
    except Exception as e:
        print(f"{COLORS['red']}[!] Error writing to log file: {str(e)}{COLORS['reset']}")


def notify_block(ip, reason):
    """Notify and log when an IP is blocked"""
    message = f"Blocked IP: {ip} - Reason: {reason}"
    print(f"{COLORS['red']}[!] {message}{COLORS['reset']}")
    log_message(message, "BLOCK")

def detect_attack(packet):
    """Detect various network attacks from packet analysis with enhanced detection logic"""
    global blocklist
    
    # Skip packets from whitelisted IPs
    if packet.haslayer(IP) and packet[IP].src in whitelist:
        return
    
    now = time.time()
    
    # TCP-based attacks
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src = packet[IP].src
        dst_port = packet[TCP].dport
        dst_ip = packet[IP].dst
        flags = packet[TCP].flags
        
        # Skip if already blocked
        if src in blocklist:
            return
            
        # Enhanced SYN Flood detection (rate-based)
        if flags == 'S':
            # Record packet timestamp for rate analysis
            if len(syn_counts[src][2]) > 20:  # Keep only last 20 timestamps
                syn_counts[src][2].pop(0)
            syn_counts[src][2].append(now)
            
            syn_counts[src][0] += 1
            syn_counts[src][1] = now
            
            # Detect rapid SYN bursts
            if len(syn_counts[src][2]) > 10:  # Need at least 10 samples
                rate = len(syn_counts[src][2]) / (syn_counts[src][2][-1] - syn_counts[src][2][0])
                if rate > 5:  # More than 5 SYNs per second is suspicious
                    log_message(f"High-rate SYN from {src}: {rate:.2f}/sec", "WARNING")
                    
            # Standard volume-based detection
            if syn_counts[src][0] > BLOCK_THRESHOLD:
                block_ip(src, f"SYN Flood Attack: {syn_counts[src][0]} attempts")

        # Advanced Port Scan detection
        connection_attempts[src][0].add(dst_port)
        connection_attempts[src][1] = now
        
        # Track per-port scan frequency
        if dst_port not in connection_attempts[src][2]:
            connection_attempts[src][2][dst_port] = 1
        else:
            connection_attempts[src][2][dst_port] += 1
            
        # More sophisticated port scan detection
        unique_ports = len(connection_attempts[src][0])
        if unique_ports > PORT_SCAN_THRESHOLD:
            # Calculate sequential port ratio
            sorted_ports = sorted(list(connection_attempts[src][0]))
            sequential = 0
            for i in range(1, len(sorted_ports)):
                if sorted_ports[i] == sorted_ports[i-1] + 1:
                    sequential += 1
            
            seq_ratio = sequential / max(len(sorted_ports) - 1, 1)
            scan_type = "Random Port Scan"
            if seq_ratio > 0.7:
                scan_type = "Sequential Port Scan"
                
            block_ip(src, f"{scan_type}: {unique_ports} ports probed")
        
        # FIN Scan detection (flags = FIN only)
        if flags == 'F':
            if 'finscan' not in connection_attempts[src][2]:
                connection_attempts[src][2]['finscan'] = 1
            else:
                connection_attempts[src][2]['finscan'] += 1
                
            if connection_attempts[src][2]['finscan'] > FINSCAN_THRESHOLD:
                block_ip(src, "FIN Scan Attack")
                
        # XMAS Scan detection (flags = FIN, PSH, URG)
        if flags == 'FPU':
            if 'xmasscan' not in connection_attempts[src][2]:
                connection_attempts[src][2]['xmasscan'] = 1
            else:
                connection_attempts[src][2]['xmasscan'] += 1
                
            if connection_attempts[src][2]['xmasscan'] > XMAS_THRESHOLD:
                block_ip(src, "XMAS Scan Attack")
        
        # NULL Scan detection (no flags)
        if flags == '':
            if 'nullscan' not in connection_attempts[src][2]:
                connection_attempts[src][2]['nullscan'] = 1
            else:
                connection_attempts[src][2]['nullscan'] += 1
                
            if connection_attempts[src][2]['nullscan'] > NULLSCAN_THRESHOLD:
                block_ip(src, "NULL Scan Attack")
        
        # Enhanced HTTP Flood detection (DOS)
        if dst_port in (80, 443, 8080):
            http_flood_counts[src][0] += 1
            http_flood_counts[src][1] = now
            
            # Extract and track HTTP User-Agent (if present in payload)
            if packet.haslayer('Raw'):
                payload = str(packet['Raw'].load)
                user_agent = re.search(r'User-Agent: (.*?)\\r\\n', payload)
                if user_agent:
                    http_flood_counts[src][2].add(user_agent.group(1))
                    
            # Detect DoS with multiple user agents or high request rate
            if http_flood_counts[src][0] > HTTP_FLOOD_THRESHOLD:
                reason = "HTTP Flood Attack"
                if len(http_flood_counts[src][2]) > 5:  # Multiple user agents
                    reason += " with multiple User-Agents"
                block_ip(src, reason)
                
        # SSL/TLS Attack detection
        if dst_port == 443 and packet.haslayer('Raw'):
            ssl_attacks[src][0] += 1
            ssl_attacks[src][1] = now
            
            payload = str(packet['Raw'].load)
            
            # Check for SSL/TLS version indicators
            if b'\x03\x00' in packet['Raw'].load:  # SSLv3
                ssl_attacks[src][2].add('SSLv3')
            if b'\x03\x01' in packet['Raw'].load:  # TLSv1.0
                ssl_attacks[src][2].add('TLSv1.0')
                
            # Check for downgrade attempts or version scanning
            if len(ssl_attacks[src][2]) >= SSL_SCAN_THRESHOLD:
                block_ip(src, f"SSL/TLS version scanning detected ({len(ssl_attacks[src][2])} versions)")
                
    # Enhanced ICMP flood detection (Ping flood)
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        src = packet[IP].src
        if src in blocklist:
            return
            
        icmp_flood_counts[src][0] += 1
        icmp_flood_counts[src][1] = now
        
        # Check both count and rate
        if icmp_flood_counts[src][0] > ICMP_FLOOD_THRESHOLD:
            block_ip(src, f"ICMP/Ping Flood Attack: {icmp_flood_counts[src][0]} packets")
    
    # Enhanced UDP flood detection
    if packet.haslayer(IP) and packet.haslayer(UDP):
        src = packet[IP].src
        dst_port = packet[UDP].dport
        
        if src in blocklist:
            return
            
        udp_flood_counts[src][0] += 1
        udp_flood_counts[src][1] = now
        
        # Calculate total bytes as well
        if packet.haslayer('Raw'):
            udp_flood_counts[src][2] += len(packet['Raw'].load)
        
        # DNS Amplification detection
        if dst_port == 53 and packet.haslayer('Raw'):
            dns_amp_counts[src][0] += 1
            dns_amp_counts[src][1] = now
            
            if packet.haslayer('Raw'):
                dns_amp_counts[src][2] += len(packet['Raw'].load)
                
            # DNS query amplification - looking for suspicious DNS traffic
            if dns_amp_counts[src][0] > DNS_AMP_THRESHOLD:
                # High number of DNS queries
                block_ip(src, f"DNS Amplification Attack: {dns_amp_counts[src][0]} queries")
        
        # Standard UDP flood
        if udp_flood_counts[src][0] > UDP_FLOOD_THRESHOLD:
            flood_size = "unknown"
            if udp_flood_counts[src][2] > 0:
                flood_size = f"{udp_flood_counts[src][2]/1024:.2f} KB"
                
            block_ip(src, f"UDP Flood Attack: {udp_flood_counts[src][0]} packets ({flood_size})")

def block_ip(ip, reason):
    """Block an IP address using iptables"""
    if ip in whitelist:
        log_message(f"Attempted to block whitelisted IP {ip}", "WARNING")
        return
        
    if ip in blocklist:
        return  # Already blocked
    
    try:
        # Block the IP with iptables
        os.system(BLOCK_COMMAND.format(ip))
        blocklist.add(ip)
        
        # Log the block
        notify_block(ip, reason)
        
        # Save to blocklist file
        log_block(ip, reason)
    except Exception as e:
        log_message(f"Error blocking IP {ip}: {str(e)}", "ERROR")


def log_block(ip, reason):
    """Save blocked IP to blocklist file"""
    try:
        os.makedirs(os.path.dirname(BLOCKLIST_FILE), exist_ok=True)
        with open(BLOCKLIST_FILE, "a") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{ip},{timestamp},{reason}\n")
    except Exception as e:
        log_message(f"Error writing to blocklist file: {str(e)}", "ERROR")


def load_blocklist():
    """Load previously blocked IPs from file"""
    try:
        if os.path.exists(BLOCKLIST_FILE):
            with open(BLOCKLIST_FILE, "r") as f:
                for line in f:
                    parts = line.strip().split(",")
                    if parts and parts[0] and parts[0] not in blocklist:
                        blocklist.add(parts[0])
                        # Re-apply the block
                        os.system(BLOCK_COMMAND.format(parts[0]))
            log_message(f"Loaded {len(blocklist)} IPs from blocklist file")
    except Exception as e:
        log_message(f"Error loading blocklist: {str(e)}", "ERROR")


def cleanup():
    """Clean up stale entries from tracking dictionaries"""
    while True:
        time.sleep(60)
        now = time.time()
        
        # Clean up all tracking dictionaries
        dictionaries = [
            syn_counts, 
            connection_attempts,
            icmp_flood_counts,
            udp_flood_counts,
            http_flood_counts,
            authentication_failures
        ]
        
        for dictionary in dictionaries:
            for ip in list(dictionary):
                if now - dictionary[ip][1] > IP_TIMEOUT:
                    del dictionary[ip]
        
        log_message(f"Cleanup completed", "DEBUG")


def cleanup_firewall():
    """Clean up iptables rules when shutting down"""
    print(f"{COLORS['yellow']}[*] IDS shutting down, cleaning up iptables rules...{COLORS['reset']}")
    for ip in blocklist:
        os.system(f"iptables -D INPUT -s {ip} -j DROP")
    log_message("Firewall cleanup complete", "INFO")

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        # Check iptables
        subprocess.check_output(["iptables", "-V"])
        
        # Check if running as root
        if os.geteuid() != 0:
            print(f"{COLORS['red']}[!] This tool needs to run as root!{COLORS['reset']}")
            print(f"    Please run with: sudo python3 {os.path.basename(__file__)}")
            return False
            
        return True
    except Exception as e:
        print(f"{COLORS['red']}[!] Error checking dependencies: {str(e)}{COLORS['reset']}")
        print(f"    Please make sure iptables is installed.")
        return False


def start_monitoring():
    """Start the network monitoring"""
    global monitoring_active, detection_running, selected_interface, program_start_time
    
    if detection_running:
        print(f"{COLORS['yellow']}[*] Monitoring is already running!{COLORS['reset']}")
        return
    
    print(f"{COLORS['green']}[+] Starting network monitoring...{COLORS['reset']}")
    monitoring_active = True
    detection_running = True
    program_start_time = time.time()
    
    # Register cleanup
    atexit.register(cleanup_firewall)
    
    # Start cleanup thread
    threading.Thread(target=cleanup, daemon=True).start()
    
    # Set signal handlers
    signal.signal(signal.SIGINT, lambda sig, frame: stop_monitoring())
    
    # Start packet sniffing in a new thread with selected interface if specified
    if selected_interface:
        print(f"{COLORS['green']}[+] Monitoring network interface: {selected_interface}{COLORS['reset']}")
        threading.Thread(target=lambda: sniff(iface=selected_interface, filter="ip", prn=detect_attack, store=0, 
                                        stop_filter=lambda x: not monitoring_active),
                     daemon=True).start()
    else:
        print(f"{COLORS['green']}[+] Monitoring all available interfaces{COLORS['reset']}")
        threading.Thread(target=lambda: sniff(filter="ip", prn=detect_attack, store=0, 
                                        stop_filter=lambda x: not monitoring_active),
                     daemon=True).start()
    
    # Show confirmation message to user
    print(f"{COLORS['cyan']}[*] Network monitoring active. Press Ctrl+C or select option 2 to stop.{COLORS['reset']}")
    input("Press Enter to return to menu...")
    
    log_message("Network monitoring started")


def stop_monitoring():
    """Stop the network monitoring"""
    global monitoring_active
    monitoring_active = False
    print(f"{COLORS['yellow']}[*] Stopping network monitoring...{COLORS['reset']}")
    log_message("Network monitoring stopped")


def show_stats():
    """Show enhanced attack statistics"""
    print(f"{COLORS['cyan']}\n===== OpenMammoth-Lite Statistics ====={COLORS['reset']}")
    print(f"\n{COLORS['white']}General Statistics:{COLORS['reset']}")
    print(f"Blocked IPs: {len(blocklist)}")
    
    # Basic attack stats
    print(f"\n{COLORS['white']}Basic Attack Detection:{COLORS['reset']}")
    print(f"SYN Flood Attacks: {len([ip for ip in syn_counts if syn_counts[ip][0] > BLOCK_THRESHOLD])}")
    print(f"Port Scans: {len([ip for ip in connection_attempts if len(connection_attempts[ip][0]) > PORT_SCAN_THRESHOLD])}")
    print(f"ICMP Flood Attacks: {len([ip for ip in icmp_flood_counts if icmp_flood_counts[ip][0] > ICMP_FLOOD_THRESHOLD])}")
    print(f"UDP Flood Attacks: {len([ip for ip in udp_flood_counts if udp_flood_counts[ip][0] > UDP_FLOOD_THRESHOLD])}")
    print(f"HTTP Flood Attacks: {len([ip for ip in http_flood_counts if http_flood_counts[ip][0] > HTTP_FLOOD_THRESHOLD])}")
    
    # Advanced attack stats
    print(f"\n{COLORS['white']}Advanced Attack Detection:{COLORS['reset']}")
    print(f"DNS Amplification Attacks: {len([ip for ip in dns_amp_counts if dns_amp_counts[ip][0] > DNS_AMP_THRESHOLD])}")
    print(f"ARP Spoofing Attempts: {len([ip for ip in arp_spoofing_attempts if len(arp_spoofing_attempts[ip][0]) > ARPSPOOF_MAC_THRESHOLD])}")
    print(f"SSL/TLS Version Scans: {len([ip for ip in ssl_attacks if len(ssl_attacks[ip][2]) >= SSL_SCAN_THRESHOLD])}")
    
    # Stealth scan stats
    print(f"\n{COLORS['white']}Stealth Scan Detection:{COLORS['reset']}")
    fin_scans = 0
    xmas_scans = 0
    null_scans = 0
    
    for ip in connection_attempts:
        scan_data = connection_attempts[ip][2]
        if scan_data.get('finscan', 0) > FINSCAN_THRESHOLD: 
            fin_scans += 1
        if scan_data.get('xmasscan', 0) > XMAS_THRESHOLD: 
            xmas_scans += 1
        if scan_data.get('nullscan', 0) > NULLSCAN_THRESHOLD: 
            null_scans += 1
            
    print(f"FIN Scans: {fin_scans}")
    print(f"XMAS Scans: {xmas_scans}")
    print(f"NULL Scans: {null_scans}")
    
    # Performance stats
    stats = {
        "memory_entries": len(syn_counts) + len(connection_attempts) + len(icmp_flood_counts) + 
                         len(udp_flood_counts) + len(http_flood_counts) + len(dns_amp_counts) + 
                         len(ssl_attacks) + len(arp_spoofing_attempts),
    }
    
    print(f"\n{COLORS['white']}Performance:{COLORS['reset']}")
    print(f"Tracking {stats['memory_entries']} unique IPs")
    print(f"Running since: {datetime.datetime.fromtimestamp(program_start_time).strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Uptime: {int(time.time() - program_start_time)} seconds")
    
    # Show blocked IP details
    if blocklist:
        print(f"\n{COLORS['cyan']}===== Blocked IPs ====={COLORS['reset']}")
        
        try:
            with open(BLOCKLIST_FILE, "r") as f:
                for line in f:
                    parts = line.strip().split(",")
                    if len(parts) >= 3:
                        ip, timestamp, reason = parts[0], parts[1], parts[2]
                        print(f"{COLORS['red']}{ip}{COLORS['reset']} - {timestamp} - {reason}")
        except Exception:
            for ip in blocklist:
                print(f"{COLORS['red']}{ip}{COLORS['reset']}")
    
    # Log file size
    try:
        if os.path.exists(LOG_FILE):
            log_size = os.path.getsize(LOG_FILE) / 1024  # KB
            print(f"\nLog size: {log_size:.2f} KB")  
    except:
        pass


def manage_whitelist():
    """Manage IP whitelist"""
    while True:
        print(f"{COLORS['cyan']}\n===== IP Whitelist Management ====={COLORS['reset']}")
        print(f"\nCurrent whitelisted IPs: {len(whitelist)}")
        
        for ip in whitelist:
            print(f"- {ip}")
        
        print("\n1. Add IP to whitelist")
        print("2. Remove IP from whitelist")
        print("0. Back to main menu")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            ip = input("Enter IP address to whitelist: ")
            if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                whitelist.add(ip)
                log_message(f"Added {ip} to whitelist")
                print(f"{COLORS['green']}[+] Added {ip} to whitelist{COLORS['reset']}")
            else:
                print(f"{COLORS['red']}[!] Invalid IP address format{COLORS['reset']}")
        elif choice == "2":
            ip = input("Enter IP address to remove from whitelist: ")
            if ip in whitelist:
                whitelist.remove(ip)
                log_message(f"Removed {ip} from whitelist")
                print(f"{COLORS['green']}[+] Removed {ip} from whitelist{COLORS['reset']}")
            else:
                print(f"{COLORS['red']}[!] IP not found in whitelist{COLORS['reset']}")
        elif choice == "0":
            break


def manage_blocklist():
    """Manage blocked IPs"""
    while True:
        print(f"{COLORS['cyan']}\n===== IP Blocklist Management ====={COLORS['reset']}")
        print(f"\nCurrent blocked IPs: {len(blocklist)}")
        
        # Show first 10 blocked IPs
        count = 0
        for ip in sorted(list(blocklist)):
            print(f"- {ip}")
            count += 1
            if count >= 10:
                print(f"... and {len(blocklist) - 10} more")
                break
        
        print("\n1. Block an IP manually")
        print("2. Unblock an IP")
        print("3. Export blocklist")
        print("0. Back to main menu")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            ip = input("Enter IP address to block: ")
            if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                block_ip(ip, "Manual block")
                print(f"{COLORS['green']}[+] Blocked {ip}{COLORS['reset']}")
            else:
                print(f"{COLORS['red']}[!] Invalid IP address format{COLORS['reset']}")
        elif choice == "2":
            ip = input("Enter IP address to unblock: ")
            if ip in blocklist:
                blocklist.remove(ip)
                os.system(f"iptables -D INPUT -s {ip} -j DROP")
                log_message(f"Manually unblocked IP: {ip}")
                print(f"{COLORS['green']}[+] Unblocked {ip}{COLORS['reset']}")
            else:
                print(f"{COLORS['red']}[!] IP not found in blocklist{COLORS['reset']}")
        elif choice == "3":
            filename = input("Enter file path to export blocklist: ")
            try:
                with open(filename, "w") as f:
                    for ip in sorted(list(blocklist)):
                        f.write(f"{ip}\n")
                print(f"{COLORS['green']}[+] Exported {len(blocklist)} IPs to {filename}{COLORS['reset']}")
            except Exception as e:
                print(f"{COLORS['red']}[!] Error exporting blocklist: {str(e)}{COLORS['reset']}")
        elif choice == "0":
            break


def select_network_interface():
    """Allow user to select a network interface for monitoring"""
    global selected_interface
    
    print(f"{COLORS['cyan']}\n===== Network Interface Selection ====={COLORS['reset']}")
    print("Available network interfaces:")
    
    interfaces = []
    try:
        # Get available interfaces using scapy's get_if_list
        from scapy.arch import get_if_list
        interfaces = get_if_list()
        
        # List all interfaces with numbers
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
            
        print(f"Current interface: {selected_interface if selected_interface else 'All (default)'}")
        
        # Let user select an interface
        choice = input("\nSelect interface number (0 for all interfaces): ")
        
        if choice == '0':
            selected_interface = None
            print(f"{COLORS['green']}[+] Using all available interfaces{COLORS['reset']}")
        elif choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            selected_interface = interfaces[int(choice)-1]
            print(f"{COLORS['green']}[+] Selected interface: {selected_interface}{COLORS['reset']}")
        else:
            print(f"{COLORS['red']}[!] Invalid choice, using all interfaces{COLORS['reset']}")
            selected_interface = None
            
    except Exception as e:
        print(f"{COLORS['red']}[!] Error getting network interfaces: {str(e)}{COLORS['reset']}")
        print(f"{COLORS['yellow']}[*] Using all available interfaces{COLORS['reset']}")
    
    input("Press Enter to continue...")


def show_attack_statistics():
    """Alias for show_stats with improved formatting"""
    show_stats()
    

def show_menu():
    """Display the main menu interface"""
    while True:
        os.system('clear' if os.name == 'posix' else 'cls')
        
        # ASCII Art logo
        print(f"{COLORS['cyan']}")
        print("  ____                   __  __                                 _   _     ")
        print(" / __ \                 |  \/  |                               | | | |   ")
        print("| |  | |_ __   ___ _ __ | \  / | __ _ _ __ ___  _ __ ___   ___ | |_| |__  ")
        print("| |  | | '_ \ / _ \ '_ \| |\/| |/ _` | '_ ` _ \| '_ ` _ \ / _ \| __| '_ \ ")
        print("| |__| | |_) |  __/ | | | |  | | (_| | | | | | | | | | | | (_) | |_| | | ||") 
        print(" \____/| .__/ \___|_| |_|_|  |_|\__,_|_| |_| |_|_| |_| |_|\___/ \__|_| |_|")
        print("       | |                                                                ")
        print("       |_|               L I T E  E D I T I O N                          ")
        print(f"{COLORS['reset']}")
        print(f"{COLORS['yellow']}Simple Network Security & Intrusion Detection System{COLORS['reset']}")
        print(f"Version 1.0.0 | Running as: {os.getlogin()}")
        print("--------------------------------------------------------")
        
        # Status info
        status = f"{COLORS['green']}ACTIVE{COLORS['reset']}" if monitoring_active else f"{COLORS['red']}INACTIVE{COLORS['reset']}"
        print(f"Monitoring Status: {status}")
        if selected_interface:
            print(f"Network Interface: {selected_interface}")
        print(f"Blocked IPs: {len(blocklist)}")
        print("--------------------------------------------------------")
        
        # Menu options
        print("\n1. Start Network Monitoring")
        print("2. Stop Network Monitoring")
        print("3. Show Attack Statistics")
        print("4. Manage IP Whitelist")
        print("5. Manage Blocked IPs")
        print("6. View System Logs")
        print("7. Select Network Interface")
        print("0. Exit")
        
        choice = input("\nSelect an option: ")
        
        if choice == "1":
            start_monitoring()
        elif choice == "2":
            stop_monitoring()
        elif choice == "3":
            show_attack_statistics()
            input("\nPress Enter to continue...")
        elif choice == "4":
            manage_whitelist()
        elif choice == "5":
            manage_blocklist()
        elif choice == "6":
            try:
                if os.path.exists(LOG_FILE):
                    os.system(f"less {LOG_FILE}")
                else:
                    print(f"{COLORS['yellow']}[*] No log file found{COLORS['reset']}")
                    input("\nPress Enter to continue...")
            except Exception:
                input("\nPress Enter to continue...")
        elif choice == "7":
            select_network_interface()
        elif choice == "0":
            if monitoring_active:
                confirm = input("Network monitoring is active. Are you sure you want to exit? (y/n): ")
                if confirm.lower() != 'y':
                    continue
            print(f"{COLORS['yellow']}[*] Exiting OpenMammoth-Lite{COLORS['reset']}")
            break
        else:
            print(f"{COLORS['red']}[!] Invalid option{COLORS['reset']}")
            time.sleep(1)


if __name__ == "__main__":
    # Initialize
    print(f"{COLORS['cyan']}[*] Starting OpenMammoth-Lite v1.0.0...{COLORS['reset']}")
    
    # Check dependencies
    if not check_dependencies():
        exit(1)
    
    # Check for Tor connections
    detect_tor_connection()
    
    # Load previously blocked IPs
    load_blocklist()
    
    try:
        # Launch the menu interface
        show_menu()
    except KeyboardInterrupt:
        print(f"\n{COLORS['yellow']}[*] Interrupted by user{COLORS['reset']}")
    except Exception as e:
        print(f"\n{COLORS['red']}[!] Error: {str(e)}{COLORS['reset']}")
    finally:
        # Ensure clean shutdown
        stop_monitoring()
        cleanup_firewall()
