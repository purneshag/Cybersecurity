import os
from scapy.all import sniff
import psutil
import time
from collections import defaultdict
from datetime import datetime

# Configuration settings
THRESHOLD = 100  # Maximum number of packets allowed per IP in a time window
TIME_WINDOW = 10  # Time window in seconds
BLOCK_DURATION = 60  # Duration to block IP in seconds

# Dictionary to keep track of packet counts and block times
packet_counts = defaultdict(int)
start_time = defaultdict(lambda: None)
blocked_ips = defaultdict(lambda: None)

def detect_dos_attack(pkt):
    """Detect potential DoS attack based on traffic patterns"""
    if pkt.haslayer('IP'):
        src_ip = pkt['IP'].src
        
        # Ignore already blocked IPs
        if blocked_ips[src_ip] is not None and (datetime.now() - blocked_ips[src_ip]).total_seconds() < BLOCK_DURATION:
            return
        
        # Initialize start time for each IP
        if start_time[src_ip] is None:
            start_time[src_ip] = datetime.now()

        # Increment packet count for this IP
        packet_counts[src_ip] += 1
        
        # Get current time and check if we're within the time window
        current_time = datetime.now()
        elapsed_time = (current_time - start_time[src_ip]).total_seconds()

        if elapsed_time > TIME_WINDOW:
            # If time window is exceeded, reset counter and start time
            packet_counts[src_ip] = 0
            start_time[src_ip] = None

        # Check if this IP has exceeded the packet threshold within the time window
        if packet_counts[src_ip] > THRESHOLD:
            print(f"[ALERT] Potential DoS Attack Detected from IP: {src_ip}")
            print(f"Start time: {start_time[src_ip]}")
            print(f"End time: {current_time}")
            
            # Mitigate attack by blocking the IP
            block_ip(src_ip)
            
            # Reset count for this IP after alerting
            packet_counts[src_ip] = 0
            start_time[src_ip] = None

def block_ip(ip):
    """Block the given IP using Windows Firewall"""
    print(f"[ACTION] Blocking IP: {ip}")
    
    # Run a command to block the IP using Windows Firewall
    block_command = f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}"
    os.system(block_command)

    # Add the IP to blocked IPs list with a timestamp
    blocked_ips[ip] = datetime.now()

def unblock_ip(ip):
    """Unblock the given IP using Windows Firewall"""
    print(f"[ACTION] Unblocking IP: {ip}")
    
    # Run a command to remove the blocking rule for the IP
    unblock_command = f"netsh advfirewall firewall delete rule name=\"Block {ip}\" remoteip={ip}"
    os.system(unblock_command)

def get_network_interface():
    """Helper function to get available network interfaces"""
    net_if_addrs = psutil.net_if_addrs()
    print("Available Network Interfaces:")
    for i, interface in enumerate(net_if_addrs.keys(), 1):
        print(f"{i}. {interface}")
    choice = int(input("Select the network interface to monitor (number): ")) - 1
    return list(net_if_addrs.keys())[choice]

def main():
    interface = get_network_interface()
    print(f"Monitoring traffic on {interface}...")

    try:
        # Sniff network traffic on the selected interface
        sniff(iface=interface, prn=detect_dos_attack, store=False)
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")

    # Optionally, unblock all IPs after the monitoring is stopped
    for ip in blocked_ips:
        unblock_ip(ip)

if __name__ == "__main__":
    main()

