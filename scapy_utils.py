from scapy.all import *
from datetime import datetime
from scapy.layers.inet import IP, TCP, UDP, ICMP

login_attempts = {}

def get_packet_size(packet):
    return len(packet)

def get_protocol_type(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    else:
        return "ICMP"

def detect_login_attempt(packet):
    login_ports = [22, 21, 80, 443]
    if packet.haslayer(TCP) and packet[TCP].dport in login_ports: #dport means destination port
        return 1
    return 0

session_start_time = {}
def get_session_duration(packet):
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    session_key = f"{src_ip}-{dst_ip}" #create unique session key based on the communication pair (e.g: 192.168.1.5-172.217.0.1)
    
    if session_key not in session_start_time: #If first time seeing this session
        session_start_time[session_key] = datetime.now()#store the current time as the start time
        return 0
    
    start_time = session_start_time[session_key]
    duration = (datetime.now() - start_time).total_seconds()
    
    return duration
