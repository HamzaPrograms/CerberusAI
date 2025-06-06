from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import socket
from collections import defaultdict
from datetime import datetime
import pandas as pd

session_start_time = {}

def get_packet_size(packet):
    return len(packet)

def get_protocol_type(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    else:
        return "ICMP"

def get_encryption_used(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 443:
        return "AES" #is acc HTTPS, but mapped to AES
    elif packet.haslayer(TCP) and packet[TCP].dport == 80:
        return "None" #is acc HTTP, but mapped to none
    else:
        return "DES" #other encryptions mapped to DES

def get_session_duration(packet):
    if not packet.haslayer(IP):
        return 0
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    session_key = f"{src_ip}-{dst_ip}"
    if session_key not in session_start_time:
        session_start_time[session_key] = datetime.now()
        return 0
    duration = (datetime.now() - session_start_time[session_key]).total_seconds()
    return duration

def get_unusual_time_access():
    hour = datetime.now().hour
    return 1 if (hour < 6 or hour > 22) else 0

def get_login_port_activity(packet):
    login_ports = [21, 22, 23, 25, 110, 143, 389, 80, 443]  # FTP, SSH, Telnet, SMTP, POP3, IMAP, HTTP(S)
    if packet.haslayer(TCP) and packet[TCP].dport in login_ports:
        return 1
    return 0

#Interpret login attempts and failed logins
attempt_log = defaultdict(list)
failed_log = defaultdict(int)
def track_login_behavior(packet):
    now = datetime.now()

    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dport = packet[TCP].dport

        # Only monitor login-related ports
        login_ports = [21, 22, 23, 25, 80, 443]
        if dport in login_ports:
            attempt_log[src_ip].append(now)

            # Clear attempts older than 10 sec
            attempt_log[src_ip] = [
                t for t in attempt_log[src_ip] if (now - t).total_seconds() <= 10
            ]

            if packet[TCP].flags == "R": #Reset connection, bc potential failed login
                failed_log[src_ip] += 1

            login_attempts = len(attempt_log[src_ip])
            failed_logins = failed_log[src_ip]
            failed_ratio = failed_logins / (login_attempts + 1)

            return login_attempts, failed_logins, failed_ratio

    return 0, 0, 0

def get_source_ip(packet):
    if packet.haslayer(IP):
        return packet[IP].src
    return None