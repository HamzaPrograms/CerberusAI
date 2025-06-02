from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import socket

session_start_time = {}

def get_packet_size(packet):
    return len(packet)

def get_protocol_type(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(IP):
        return "IP"
    else:
        return "OTHER"

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

# Add more feature functions as needed...
