import os
import smtplib
import threading
from scapy.all import sniff
import psutil
import time
from collections import defaultdict
from datetime import datetime
from email.mime.text import MIMEText

# Configuration settings
THRESHOLD = 100 # Maximum number of packets allowed per IP in a time window
TIME_WINDOW = 10  # Time window in seconds
BLOCK_DURATION = 60 # Duration to block IP in seconds
REPORT_INTERVAL = 20  # Interval in seconds for reporting attack status
EMAIL_INTERVAL = 60  # Minimum interval to send email alerts
LOG_FILE = "attack_logs.txt"  # File to store attack logs
ADMIN_EMAIL = "admin@example.com"  # Replace with admin email address
SMTP_SERVER = "smtp.example.com"  # Replace with SMTP server
SMTP_PORT = 587  # SMTP port
EMAIL_USER = "your_email@example.com" # Replace with your email address
EMAIL_PASSWORD = "your_password"  # Replace with your email password

# List of whitelisted IPs
WHITELISTED_IPS = ["192.168.1.1", "127.0.0.1"]

# Dictionary to keep track of packet counts, block times, and attack times
packet_counts = defaultdict(int)
start_time = defaultdict(lambda: None)
blocked_ips = defaultdict(lambda: None)
attack_detected = False
last_email_sent = None

def log_message(message):
    """Logs a message to the log file and prints to the console."""
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(f"{datetime.now()} - {message}\n")
    print(message)

def detect_dos_attack(pkt):
    """Detect potential DoS attack based on traffic patterns"""
    global attack_detected, last_email_sent
    if pkt.haslayer('IP'):
        src_ip = pkt['IP'].src

        # Ignore whitelisted IPs
        if src_ip in WHITELISTED_IPS:
            return
        
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
            attack_detected = True
            log_message(f"[ALERT] Potential DoS Attack Detected from IP: {src_ip}")
            log_message(f"Start time: {start_time[src_ip]}")
            log_message(f"End time: {current_time}")
            
            # Mitigate attack by blocking the IP
            block_ip(src_ip)
            
            # Reset count for this IP after alerting
            packet_counts[src_ip] = 0
            start_time[src_ip] = None

            # Send an email alert if enough time has passed since the last alert
            if last_email_sent is None or (current_time - last_email_sent).total_seconds() > EMAIL_INTERVAL:
                send_email_alert(src_ip, start_time[src_ip], current_time)
                last_email_sent = current_time
        else:
            attack_detected = False

def block_ip(ip):
    """Block the given IP using Windows Firewall"""
    log_message(f"[ACTION] Blocking IP: {ip}")
    
    # Run a command to block the IP using Windows Firewall
    block_command = f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}"
    os.system(block_command)

    # Add the IP to blocked IPs list with a timestamp
    blocked_ips[ip] = datetime.now()

def unblock_ip(ip):
    """Unblock the given IP using Windows Firewall"""
    log_message(f"[ACTION] Unblocking IP: {ip}")
    
    # Run a command to remove the blocking rule for the IP
    unblock_command = f"netsh advfirewall firewall delete rule name=\"Block {ip}\" remoteip={ip}"
    os.system(unblock_command)

def send_email_alert(ip, start_time, end_time):
    """Send an email alert to administrators when an attack is detected"""
    log_message(f"[EMAIL] Sending alert for IP: {ip}")
    subject = f"DoS Attack Alert: {ip}"
    body = f"A DoS attack has been detected from IP address {ip}.\nStart Time: {start_time}\nEnd Time: {end_time}\nThe IP has been blocked."
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = EMAIL_USER
    msg['To'] = ADMIN_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, ADMIN_EMAIL, msg.as_string())
        log_message(f"[EMAIL] Alert sent successfully to {ADMIN_EMAIL}")
    except Exception as e:
        log_message(f"[ERROR] Failed to send email: {str(e)}")

def report_status():
    """Periodically report the attack status"""
    global attack_detected
    while True:
        if attack_detected:
            log_message("[STATUS] Attack Detected")
        else:
            log_message("[STATUS] No Attack Detected")
        time.sleep(REPORT_INTERVAL)

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
    log_message(f"Monitoring traffic on {interface}...")

    # Start the status reporting thread
    status_thread = threading.Thread(target=report_status)
    status_thread.daemon = True  # Ensures the thread exits when the main program does
    status_thread.start()

    try:
        # Sniff network traffic on the selected interface
        sniff(iface=interface, prn=detect_dos_attack, store=False)
    except KeyboardInterrupt:
        log_message("Monitoring stopped.")

    # Optionally, unblock all IPs after the monitoring is stopped
    for ip in blocked_ips:
        unblock_ip(ip)

if __name__ == "__main__":
    main()

