#!/usr/bin/env python3
"""
G66 Network Forensic Analysis Platform
Case Study: RIG Exploit Kit Drive-by Infection Delivering KPOT Stealer
Group: G66 | Cyber Security CA-2
"""

import os
import sys
import hashlib
import json
import csv
import io
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, send_file
from werkzeug.utils import secure_filename

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Optional/Safe Scapy import
try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, DNS, DNSQR, Raw, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = 'g66-forensics-secret-key-2026'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB limit
ALLOWED_EXTENSIONS = {'pcap', 'pcapng'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Reference Case Study Indicators (Group G66)
REFERENCE_IOCS = [
    {
        "id": "IOC-001",
        "type": "IP Address (Victim)",
        "value": "10.0.76.109",
        "category": "Suspected Infected Host",
        "evidence_source": "Case Study Reference / DHCP Lease",
        "severity": "High",
        "description": "Internal workstation IP assigned to BANGKOK-8AC2-PC, endpoint targeted by RIG exploit kit.",
        "attack_stage": "Victim Endpoint"
    },
    {
        "id": "IOC-002",
        "type": "Hostname",
        "value": "BANGKOK-8AC2-PC",
        "category": "Victim Host Identity",
        "evidence_source": "Case Study Reference / NetBIOS / Kerberos",
        "severity": "Medium",
        "description": "Identified internal client computer name executing vulnerable browser session.",
        "attack_stage": "Victim Endpoint"
    },
    {
        "id": "IOC-003",
        "type": "MAC Address",
        "value": "78:2b:cb:d4:a5:fe",
        "category": "Victim Hardware Identifier",
        "evidence_source": "Case Study Reference / Ethernet Frame",
        "severity": "Medium",
        "description": "Hardware MAC address associated with infected endpoint workstation interface.",
        "attack_stage": "Victim Endpoint"
    },
    {
        "id": "IOC-004",
        "type": "IP Address (Malicious)",
        "value": "37.46.135.170",
        "category": "Malware Delivery / Exploit Server",
        "evidence_source": "Case Study Reference / Traffic Capture",
        "severity": "Critical",
        "description": "Reported RIG Exploit Kit landing host hosting exploit gate and payload binaries.",
        "attack_stage": "Exploit Delivery (RIG EK)"
    },
    {
        "id": "IOC-005",
        "type": "IP Address (C2)",
        "value": "8.209.83.76",
        "category": "Command & Control (C2)",
        "evidence_source": "Case Study Reference / External Connection",
        "severity": "Critical",
        "description": "Reported Command and Control server receiving credential exfiltration from KPOT Stealer.",
        "attack_stage": "Command & Control / Exfiltration"
    },
    {
        "id": "IOC-006",
        "type": "Domain Name",
        "value": "fghjkmgru34.site",
        "category": "C2 Domain",
        "evidence_source": "Case Study Reference / DNS Resolution",
        "severity": "Critical",
        "description": "Suspicious top-level domain queried by infected host resolving to C2 host 8.209.83.76.",
        "attack_stage": "Command & Control Resolution"
    },
    {
        "id": "IOC-007",
        "type": "URI / URL Path",
        "value": "/gate.php",
        "category": "Malware Exfiltration Gate",
        "evidence_source": "Case Study Reference / HTTP POST Session",
        "severity": "Critical",
        "description": "HTTP POST endpoint utilized by KPOT Stealer for sending stolen browser credentials and system discovery data.",
        "attack_stage": "Credential Exfiltration"
    },
    {
        "id": "IOC-008",
        "type": "Malware Family",
        "value": "KPOT Stealer",
        "category": "Information Stealer Trojan",
        "evidence_source": "Case Study Reference / Payload Profile",
        "severity": "Critical",
        "description": "Lightweight modular infostealer designed to exfiltrate passwords, crypto wallets, and browser cookies.",
        "attack_stage": "Payload Execution"
    }
]

# MITRE ATT&CK Mapping
MITRE_FRAMEWORK = [
    {
        "tactic": "Initial Access",
        "id": "T1189",
        "name": "Drive-by Compromise",
        "status": "Corroborated / High Lead",
        "description": "User browsed an uncompromised or malvertising-injected site redirecting to RIG EK landing page.",
        "confidence": "High"
    },
    {
        "tactic": "Execution",
        "id": "T1203",
        "name": "Exploitation for Client Execution",
        "status": "Inferred Forensic Lead",
        "description": "RIG EK leveraged browser/plugin vulnerability (Flash/VBScript/CVE) to execute shellcode silently in memory.",
        "confidence": "Medium (Requires memory forensic correlation)"
    },
    {
        "tactic": "Defense Evasion",
        "id": "T1027",
        "name": "Obfuscated Files or Information",
        "status": "Observed Lead",
        "description": "Exploit kit scripts and initial dropper payloads packed with multi-layer obfuscation to evade static detection.",
        "confidence": "High"
    },
    {
        "tactic": "Credential Access",
        "id": "T1555",
        "name": "Credentials from Password Stores",
        "status": "Inferred from Malware Profile",
        "description": "KPOT Stealer extracts saved credentials from Chromium, Firefox, Thunderbird, and crypto wallets.",
        "confidence": "High"
    },
    {
        "tactic": "Discovery",
        "id": "T1082",
        "name": "System Information Discovery",
        "status": "Inferred Lead",
        "description": "Harvests Windows machine name (BANGKOK-8AC2-PC), OS build, active user, and screen resolution before beaconing.",
        "confidence": "High"
    },
    {
        "tactic": "Command & Control",
        "id": "T1071.001",
        "name": "Web Protocols: HTTP/HTTPS",
        "status": "Directly Observed",
        "description": "Outbound HTTP POST traffic to fghjkmgru34.site/gate.php on port 80 bypassing standard egress controls.",
        "confidence": "Confirmed"
    },
    {
        "tactic": "Exfiltration",
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "status": "Directly Observed",
        "description": "Encrypted victim telemetry and credentials sent in HTTP payload body to gate.php.",
        "confidence": "Confirmed"
    }
]

# Global In-Memory Analysis State
current_state = {
    "mode": "demo",          # "demo", "pcap", or "empty"
    "file_name": "Synthetic_RIG_KPOT_Case_Study.pcap",
    "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "file_size": "142.8 KB",
    "upload_timestamp": "2026-10-10 13:45:00 UTC",
    "packets": [],
    "iocs": [],
    "timeline": [],
    "stats": {},
    "analyst_notes": "Initial triage: Host 10.0.76.109 exhibits classic RIG Exploit Kit drive-by sequence culminating in KPOT stealer exfiltration beaconing to /gate.php."
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_sha256(filepath):
    """Calculates SHA-256 hash of evidence file for forensic chain of custody."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_synthetic_demo_data():
    """
    Generates a realistic synthetic forensic dataset reflecting the
    RIG Exploit Kit + KPOT Stealer case study alongside normal background enterprise traffic.
    """
    packets = []
    base_time = 1565784000.0  # Reference epoch timestamp

    # Helper to append synthetic packet
    def add_pkt(idx, rel_sec, src, dst, proto, sport, dport, length, info, is_suspicious=False, susp_reason="", payload_snippet="", dns_q="", http_meta=None):
        ts = datetime.fromtimestamp(base_time + rel_sec).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        packets.append({
            "packet_no": idx,
            "timestamp": ts,
            "epoch": base_time + rel_sec,
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "src_port": sport,
            "dst_port": dport,
            "length": length,
            "info": info,
            "is_suspicious": is_suspicious,
            "suspicious_reason": susp_reason,
            "payload_snippet": payload_snippet,
            "dns_query": dns_q,
            "http_meta": http_meta or {},
            "mac_src": "78:2b:cb:d4:a5:fe" if src == "10.0.76.109" else "52:54:00:12:34:56",
            "mac_dst": "52:54:00:12:34:56" if src == "10.0.76.109" else "78:2b:cb:d4:a5:fe",
            "evidence_type": "Synthetic (Demo Data)"
        })

    pkt_id = 1

    # Stage 0: Normal Network Baseline Traffic
    add_pkt(pkt_id, 0.05, "10.0.76.109", "10.0.76.1", "ARP", 0, 0, 42, "Who has 10.0.76.1? Tell 10.0.76.109"); pkt_id += 1
    add_pkt(pkt_id, 0.08, "10.0.76.1", "10.0.76.109", "ARP", 0, 0, 42, "10.0.76.1 is at 52:54:00:12:34:56"); pkt_id += 1
    add_pkt(pkt_id, 0.21, "10.0.76.109", "10.0.76.1", "DNS", 52140, 53, 74, "Standard query A connectivitycheck.gstatic.com", dns_q="connectivitycheck.gstatic.com"); pkt_id += 1
    add_pkt(pkt_id, 0.24, "10.0.76.1", "10.0.76.109", "DNS", 53, 52140, 90, "Standard query response A 172.217.160.131", dns_q="connectivitycheck.gstatic.com"); pkt_id += 1
    add_pkt(pkt_id, 0.35, "10.0.76.109", "172.217.160.131", "TCP", 49182, 80, 66, "[SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256"); pkt_id += 1
    add_pkt(pkt_id, 0.40, "172.217.160.131", "10.0.76.109", "TCP", 80, 49182, 66, "[SYN, ACK] Seq=0 Ack=1 Win=28960 Len=0"); pkt_id += 1
    add_pkt(pkt_id, 0.42, "10.0.76.109", "172.217.160.131", "HTTP", 49182, 80, 185, "GET /generate_204 HTTP/1.1", http_meta={"method": "GET", "path": "/generate_204", "host": "connectivitycheck.gstatic.com"}); pkt_id += 1
    add_pkt(pkt_id, 0.48, "172.217.160.131", "10.0.76.109", "HTTP", 80, 49182, 142, "HTTP/1.1 204 No Content"); pkt_id += 1

    # Stage 1: Compromised Web Page / Ad Redirect
    add_pkt(pkt_id, 1.15, "10.0.76.109", "10.0.76.1", "DNS", 53310, 53, 76, "Standard query A news-feed-portal.info", dns_q="news-feed-portal.info"); pkt_id += 1
    add_pkt(pkt_id, 1.20, "10.0.76.1", "10.0.76.109", "DNS", 53, 53310, 92, "Standard query response A 185.190.140.22", dns_q="news-feed-portal.info"); pkt_id += 1
    add_pkt(pkt_id, 1.30, "10.0.76.109", "185.190.140.22", "TCP", 49185, 80, 66, "[SYN] Seq=0 Win=64240 Len=0"); pkt_id += 1
    add_pkt(pkt_id, 1.35, "185.190.140.22", "10.0.76.109", "TCP", 80, 49185, 66, "[SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0"); pkt_id += 1
    add_pkt(pkt_id, 1.37, "10.0.76.109", "185.190.140.22", "HTTP", 49185, 80, 412, "GET /index.php HTTP/1.1 (User-Agent: Mozilla/5.0 MSIE 11.0)", http_meta={"method": "GET", "path": "/index.php", "host": "news-feed-portal.info"}); pkt_id += 1
    add_pkt(pkt_id, 1.52, "185.190.140.22", "10.0.76.109", "HTTP", 80, 49185, 1480, "HTTP/1.1 200 OK (Contains obfuscated iframe script -> 37.46.135.170)", is_suspicious=True, susp_reason="Hidden malicious iframe injection redirecting user to exploit gate", payload_snippet="<script>var _0x9f=['src','http://37.46.135.170/?gate_token=90a8...']...</script>"); pkt_id += 1

    # Stage 2: RIG Exploit Kit Landing & Vulnerability Exploitation
    add_pkt(pkt_id, 2.10, "10.0.76.109", "37.46.135.170", "TCP", 49190, 80, 66, "[SYN] RIG Exploit Gate Connection", is_suspicious=True, susp_reason="Direct TCP connection to reported RIG Exploit Kit Delivery IP 37.46.135.170"); pkt_id += 1
    add_pkt(pkt_id, 2.14, "37.46.135.170", "10.0.76.109", "TCP", 80, 49190, 66, "[SYN, ACK] Handshake acknowledged"); pkt_id += 1
    add_pkt(pkt_id, 2.18, "10.0.76.109", "37.46.135.170", "HTTP", 49190, 80, 395, "GET /?gate_token=90a84c2f10b HTTP/1.1", is_suspicious=True, susp_reason="RIG EK Landing Page request with session token", http_meta={"method": "GET", "path": "/?gate_token=90a84c2f10b", "host": "37.46.135.170"}); pkt_id += 1
    add_pkt(pkt_id, 2.35, "37.46.135.170", "10.0.76.109", "HTTP", 80, 49190, 4820, "HTTP/1.1 200 OK (RIG Exploit Landing: VBScript / Flash SWF trigger)", is_suspicious=True, susp_reason="RIG EK Landing containing client profiler and CVE exploit shellcode", payload_snippet="<html><body><script language='VBScript'>Execute(Unescape('%0D%0A%76%61%72%20...'))</script></body></html>"); pkt_id += 1

    # Stage 3: Exploit Execution & Malware Dropper Delivery
    add_pkt(pkt_id, 3.40, "10.0.76.109", "37.46.135.170", "TCP", 49192, 80, 66, "[SYN] Exploit payload request channel"); pkt_id += 1
    add_pkt(pkt_id, 3.48, "10.0.76.109", "37.46.135.170", "HTTP", 49192, 80, 340, "GET /payload.bin HTTP/1.1", is_suspicious=True, susp_reason="Direct binary payload request following RIG landing execution", http_meta={"method": "GET", "path": "/payload.bin", "host": "37.46.135.170"}); pkt_id += 1
    add_pkt(pkt_id, 3.75, "37.46.135.170", "10.0.76.109", "HTTP", 80, 49192, 16384, "HTTP/1.1 200 OK (Binary payload stream: Encrypted KPOT Stealer PE)", is_suspicious=True, susp_reason="Transfer of binary payload identified as KPOT Stealer variant", payload_snippet="MZ..................@.............................................This program cannot be run in DOS mode..."); pkt_id += 1

    # Stage 4: Background Windows & Protocol Activity
    add_pkt(pkt_id, 4.20, "10.0.76.109", "239.255.255.250", "UDP", 1900, 1900, 175, "SSDP M-SEARCH * HTTP/1.1"); pkt_id += 1
    add_pkt(pkt_id, 4.80, "10.0.76.109", "10.0.76.1", "DNS", 54102, 53, 68, "Standard query A time.windows.com", dns_q="time.windows.com"); pkt_id += 1
    add_pkt(pkt_id, 4.85, "10.0.76.1", "10.0.76.109", "DNS", 53, 54102, 84, "Standard query response A 51.145.123.29", dns_q="time.windows.com"); pkt_id += 1
    add_pkt(pkt_id, 5.01, "10.0.76.109", "51.145.123.29", "UDP", 123, 123, 76, "NTP client request (Client: BANGKOK-8AC2-PC)"); pkt_id += 1

    # Stage 5: KPOT Stealer C2 DNS Resolution
    add_pkt(pkt_id, 6.12, "10.0.76.109", "10.0.76.1", "DNS", 55219, 53, 79, "Standard query A fghjkmgru34.site", is_suspicious=True, susp_reason="DNS lookup for reported KPOT Stealer C2 domain fghjkmgru34.site", dns_q="fghjkmgru34.site"); pkt_id += 1
    add_pkt(pkt_id, 6.18, "10.0.76.1", "10.0.76.109", "DNS", 53, 55219, 95, "Standard query response A 8.209.83.76", is_suspicious=True, susp_reason="DNS response mapping C2 domain to reported C2 IP 8.209.83.76", dns_q="fghjkmgru34.site"); pkt_id += 1

    # Stage 6: KPOT Stealer Exfiltration via HTTP POST /gate.php
    add_pkt(pkt_id, 6.45, "10.0.76.109", "8.209.83.76", "TCP", 49201, 80, 66, "[SYN] C2 Channel Initiated", is_suspicious=True, susp_reason="Direct TCP handshake with external C2 IP 8.209.83.76"); pkt_id += 1
    add_pkt(pkt_id, 6.50, "8.209.83.76", "10.0.76.109", "TCP", 80, 49201, 66, "[SYN, ACK] Seq=0 Ack=1 Win=14600 Len=0"); pkt_id += 1
    add_pkt(pkt_id, 6.55, "10.0.76.109", "8.209.83.76", "HTTP", 49201, 80, 1240, "POST /gate.php HTTP/1.1 (C2 Beacon / System Profiling)", is_suspicious=True, susp_reason="Suspicious HTTP POST to /gate.php on C2 host. Matches KPOT Stealer telemetry exfiltration.", http_meta={"method": "POST", "path": "/gate.php", "host": "fghjkmgru34.site"}, payload_snippet="POST /gate.php HTTP/1.1\r\nHost: fghjkmgru34.site\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\r\nContent-Length: 942\r\n\r\ndata=7B22686F7374223A2242414E474B4F4B2D384143322D5043222C2275736572223A2256696374696D222C226372656473223A5B...7D"); pkt_id += 1
    add_pkt(pkt_id, 6.75, "8.209.83.76", "10.0.76.109", "HTTP", 80, 49201, 218, "HTTP/1.1 200 OK (C2 Ack: OK / Command: sleep 3600)", is_suspicious=True, susp_reason="C2 Server command acknowledge receipt of stolen credentials", payload_snippet="HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nSTATUS:OK;TASK:SLEEP:3600"); pkt_id += 1

    # Stage 7: Subsequent Periodic Exfiltration Beacons & Normal Traffic
    add_pkt(pkt_id, 8.10, "10.0.76.109", "8.209.83.76", "HTTP", 49208, 80, 2410, "POST /gate.php HTTP/1.1 (Secondary Credential Exfiltration Batch)", is_suspicious=True, susp_reason="KPOT Stealer exfiltrating browser autofill and cookie vault", http_meta={"method": "POST", "path": "/gate.php", "host": "fghjkmgru34.site"}, payload_snippet="POST /gate.php HTTP/1.1\r\nHost: fghjkmgru34.site\r\nContent-Length: 2110\r\n\r\n[Encrypted Binary/Base64 Stream: Chrome_Cookies_Vault]"); pkt_id += 1
    add_pkt(pkt_id, 8.25, "8.209.83.76", "10.0.76.109", "HTTP", 80, 49208, 180, "HTTP/1.1 200 OK (Gate Received)", is_suspicious=True, susp_reason="C2 response to secondary exfiltration beacon"); pkt_id += 1

    # Add realistic padding traffic to reach a good demo size (~45 packets)
    for i in range(1, 20):
        t_pad = 9.0 + (i * 0.4)
        if i % 3 == 0:
            add_pkt(pkt_id, t_pad, "10.0.76.109", "1.1.1.1", "DNS", 56000 + i, 53, 72, f"Standard query A cdn-update-{i}.org", dns_q=f"cdn-update-{i}.org")
        elif i % 2 == 0:
            add_pkt(pkt_id, t_pad, "10.0.76.109", "142.250.190.46", "TLS", 49220 + i, 443, 517, "Application Data (TLSv1.3 Encrypted Session)")
        else:
            add_pkt(pkt_id, t_pad, "10.0.76.109", "10.0.76.1", "TCP", 49230 + i, 445, 66, "[ACK] SMB Keep-Alive")
        pkt_id += 1

    # Construct Attack Timeline
    timeline = [
        {
            "step": 1,
            "stage": "Compromised Webpage Visit",
            "timestamp": "2019-08-14 12:00:01 UTC",
            "type": "Directly Observed Evidence",
            "headline": "Infected Client Requests news-feed-portal.info",
            "details": "Client BANGKOK-8AC2-PC (10.0.76.109) visits website containing an embedded obfuscated script redirecting traffic to RIG EK.",
            "source_ip": "10.0.76.109",
            "dest_ip": "185.190.140.22",
            "protocol": "HTTP",
            "mitre": "T1189 - Drive-by Compromise",
            "evidence_status": "Observed in Packet #6-#7"
        },
        {
            "step": 2,
            "stage": "RIG Exploit Kit Landing",
            "timestamp": "2019-08-14 12:00:02 UTC",
            "type": "Directly Observed Evidence",
            "headline": "Connection to Reported RIG Delivery Host 37.46.135.170",
            "details": "Victim browser executes redirection gate token, downloading multi-part obfuscated exploit landing page.",
            "source_ip": "10.0.76.109",
            "dest_ip": "37.46.135.170",
            "protocol": "HTTP",
            "mitre": "T1203 - Client Exploitation",
            "evidence_status": "Observed in Packet #8-#10"
        },
        {
            "step": 3,
            "stage": "Malware Payload Delivery",
            "timestamp": "2019-08-14 12:00:03 UTC",
            "type": "Directly Observed Evidence",
            "headline": "Executable Dropper Transferred (/payload.bin)",
            "details": "Following successful exploitation, victim client requests payload.bin, pulling the packed KPOT Stealer binary.",
            "source_ip": "10.0.76.109",
            "dest_ip": "37.46.135.170",
            "protocol": "HTTP",
            "mitre": "T1027 - Obfuscated Payload",
            "evidence_status": "Observed in Packet #11-#13"
        },
        {
            "step": 4,
            "stage": "Suspected KPOT Stealer Execution",
            "timestamp": "2019-08-14 12:00:04 - 12:00:05 UTC",
            "type": "Analyst Interpretation (Host Execution)",
            "headline": "Memory Execution & Host Profiling",
            "details": "Client executes KPOT Stealer; queries local system information (hostname BANGKOK-8AC2-PC, MAC 78:2b:cb:d4:a5:fe) and prepares credential loot.",
            "source_ip": "10.0.76.109",
            "dest_ip": "Local Endpoint",
            "protocol": "Internal / System",
            "mitre": "T1082 / T1555 - Discovery & Credential Stealing",
            "evidence_status": "Inferred from Subsequent C2 Telemetry"
        },
        {
            "step": 5,
            "stage": "C2 Domain Resolution",
            "timestamp": "2019-08-14 12:00:06 UTC",
            "type": "Directly Observed Evidence",
            "headline": "DNS Query for fghjkmgru34.site",
            "details": "Client resolves malicious domain fghjkmgru34.site, receiving A record response pointing to 8.209.83.76.",
            "source_ip": "10.0.76.109",
            "dest_ip": "10.0.76.1 (DNS)",
            "protocol": "DNS",
            "mitre": "T1071.001 - Application Layer C2",
            "evidence_status": "Observed in Packet #18-#19"
        },
        {
            "step": 6,
            "stage": "Credential Exfiltration Beacon",
            "timestamp": "2019-08-14 12:00:06 - 12:00:08 UTC",
            "type": "Directly Observed Evidence",
            "headline": "HTTP POST to fghjkmgru34.site/gate.php",
            "details": "KPOT Stealer performs outbound HTTP POST to /gate.php exfiltrating harvested victim system information and browser credentials.",
            "source_ip": "10.0.76.109",
            "dest_ip": "8.209.83.76",
            "protocol": "HTTP POST",
            "mitre": "T1041 - Exfiltration Over C2 Channel",
            "evidence_status": "Observed in Packet #22 & #24"
        }
    ]

    # Build IOCs list with status for demo
    iocs = []
    for ref in REFERENCE_IOCS:
        ioc_copy = dict(ref)
        ioc_copy["validation_status"] = "Corroborated in Synthetic Demo Profile"
        ioc_copy["match_count"] = 1
        if ref["value"] == "10.0.76.109":
            ioc_copy["match_count"] = sum(1 for p in packets if p["src_ip"] == "10.0.76.109" or p["dst_ip"] == "10.0.76.109")
        elif ref["value"] == "37.46.135.170":
            ioc_copy["match_count"] = sum(1 for p in packets if p["src_ip"] == "37.46.135.170" or p["dst_ip"] == "37.46.135.170")
        elif ref["value"] == "8.209.83.76":
            ioc_copy["match_count"] = sum(1 for p in packets if p["src_ip"] == "8.209.83.76" or p["dst_ip"] == "8.209.83.76")
        elif ref["value"] == "fghjkmgru34.site":
            ioc_copy["match_count"] = sum(1 for p in packets if ref["value"] in p.get("dns_query", "") or ref["value"] in str(p.get("http_meta", {})))
        elif ref["value"] == "/gate.php":
            ioc_copy["match_count"] = sum(1 for p in packets if ref["value"] in str(p.get("http_meta", {})))
        iocs.append(ioc_copy)

    # Compute Statistics
    stats = compute_statistics(packets)

    return packets, iocs, timeline, stats

def compute_statistics(packets):
    """Computes summary metrics, protocol breakdowns, and timeline distributions."""
    if not packets:
        return {
            "total_packets": 0,
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "http_requests": 0,
            "dns_queries": 0,
            "suspicious_events": 0,
            "protocols": {},
            "top_talkers_src": [],
            "top_talkers_dst": [],
            "traffic_time_series": {"labels": [], "counts": []}
        }

    src_ips = set()
    dst_ips = set()
    proto_counts = {}
    src_counts = {}
    dst_counts = {}
    http_count = 0
    dns_count = 0
    suspicious_count = 0

    # Bucket time series by relative order or timestamp intervals
    time_buckets = {}

    for p in packets:
        src = p.get("src_ip", "Unknown")
        dst = p.get("dst_ip", "Unknown")
        proto = p.get("protocol", "Other")

        if src:
            src_ips.add(src)
            src_counts[src] = src_counts.get(src, 0) + 1
        if dst:
            dst_ips.add(dst)
            dst_counts[dst] = dst_counts.get(dst, 0) + 1

        proto_counts[proto] = proto_counts.get(proto, 0) + 1

        if p.get("is_suspicious"):
            suspicious_count += 1
        if proto == "HTTP" or (p.get("http_meta") and p["http_meta"].get("method")):
            http_count += 1
        if proto == "DNS" or p.get("dns_query"):
            dns_count += 1

        # Time series grouping (minute or second bucket)
        ts_str = p.get("timestamp", "")
        # Use first 19 chars: "YYYY-MM-DD HH:MM:SS" or second index
        bucket_key = ts_str[:19] if len(ts_str) >= 19 else f"Packet #{p.get('packet_no')}"
        time_buckets[bucket_key] = time_buckets.get(bucket_key, 0) + 1

    top_src = sorted([{"ip": k, "count": v} for k, v in src_counts.items()], key=lambda x: x["count"], reverse=True)[:5]
    top_dst = sorted([{"ip": k, "count": v} for k, v in dst_counts.items()], key=lambda x: x["count"], reverse=True)[:5]

    sorted_buckets = sorted(time_buckets.items())
    time_series = {
        "labels": [b[0].split(' ')[-1] if ' ' in b[0] else b[0] for b in sorted_buckets[:15]],
        "counts": [b[1] for b in sorted_buckets[:15]]
    }

    return {
        "total_packets": len(packets),
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "http_requests": http_count,
        "dns_queries": dns_count,
        "suspicious_events": suspicious_count,
        "protocols": proto_counts,
        "top_talkers_src": top_src,
        "top_talkers_dst": top_dst,
        "traffic_time_series": time_series
    }

def parse_real_pcap(filepath):
    """
    Parses an uploaded PCAP/PCAPNG file using Scapy.
    Extracts forensic fields, matches against case study IOCs, and tags suspicious activity.
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy library is not installed on the system. Cannot parse binary PCAP.")

    scapy_pkts = rdpcap(filepath)
    packets = []
    suspicious_packets = []

    # Case study reference values for matching
    ref_ips = {"10.0.76.109", "37.46.135.170", "8.209.83.76"}
    ref_domains = {"fghjkmgru34.site"}
    ref_paths = {"/gate.php"}
    ref_macs = {"78:2b:cb:d4:a5:fe"}

    for idx, pkt in enumerate(scapy_pkts, start=1):
        try:
            # Timestamp
            pkt_time = float(pkt.time)
            ts = datetime.fromtimestamp(pkt_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

            # Length
            pkt_len = len(pkt)

            # Ethernet / MAC
            mac_src = pkt[Ether].src if pkt.haslayer(Ether) else ""
            mac_dst = pkt[Ether].dst if pkt.haslayer(Ether) else ""

            # IPs
            src_ip = ""
            dst_ip = ""
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
            elif pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst

            # Protocol & Ports
            proto = "Other"
            sport = 0
            dport = 0
            dns_q = ""
            http_meta = {}
            payload_str = ""

            if pkt.haslayer(ARP):
                proto = "ARP"
            elif pkt.haslayer(DNS) or (pkt.haslayer(UDP) and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53)):
                proto = "DNS"
                if pkt.haslayer(UDP):
                    sport = pkt[UDP].sport
                    dport = pkt[UDP].dport
                if pkt.haslayer(DNSQR):
                    try:
                        qname = pkt[DNSQR].qname
                        dns_q = qname.decode('utf-8', errors='ignore').rstrip('.')
                    except Exception:
                        dns_q = str(pkt[DNSQR].qname)
            elif pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                if sport == 443 or dport == 443:
                    proto = "TLS/HTTPS"
                elif sport == 80 or dport == 80 or sport == 8080 or dport == 8080:
                    proto = "HTTP"
                else:
                    proto = "TCP"
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                proto = "UDP"

            # Raw Payload Inspection
            if pkt.haslayer(Raw):
                raw_bytes = pkt[Raw].load
                payload_str = raw_bytes.decode('latin-1', errors='ignore')

                # Check if payload is HTTP
                if any(payload_str.startswith(method) for method in ['GET ', 'POST ', 'HEAD ', 'HTTP/1.', 'PUT ']):
                    proto = "HTTP"
                    lines = payload_str.split('\r\n')
                    first_line = lines[0] if lines else ""
                    parts = first_line.split(' ')
                    if len(parts) >= 2:
                        http_meta["method"] = parts[0]
                        http_meta["path"] = parts[1]
                    for line in lines[1:]:
                        if line.lower().startswith('host:'):
                            http_meta["host"] = line.split(':', 1)[1].strip()
                        elif line.lower().startswith('user-agent:'):
                            http_meta["user_agent"] = line.split(':', 1)[1].strip()

            # Formulate Info line
            info_text = f"{proto} {src_ip}:{sport} -> {dst_ip}:{dport} Len={pkt_len}"
            if proto == "DNS" and dns_q:
                info_text = f"DNS Query: {dns_q}"
            elif proto == "HTTP" and http_meta.get("method"):
                info_text = f"HTTP {http_meta.get('method')} {http_meta.get('path', '')} (Host: {http_meta.get('host', '')})"
            elif proto == "ARP":
                info_text = f"ARP Request/Reply: {src_ip} -> {dst_ip}"

            # Suspicious Correlation Engine
            is_suspicious = False
            susp_reasons = []

            # Check case study IOCs
            if src_ip in ref_ips or dst_ip in ref_ips:
                is_suspicious = True
                if "10.0.76.109" in (src_ip, dst_ip):
                    susp_reasons.append("Involves suspected infected host 10.0.76.109")
                if "37.46.135.170" in (src_ip, dst_ip):
                    susp_reasons.append("Involves RIG Exploit delivery host 37.46.135.170")
                if "8.209.83.76" in (src_ip, dst_ip):
                    susp_reasons.append("Involves KPOT Stealer C2 host 8.209.83.76")

            if dns_q and any(ref_d in dns_q.lower() for ref_d in ref_domains):
                is_suspicious = True
                susp_reasons.append(f"DNS lookup for KPOT C2 domain {dns_q}")

            if http_meta.get("path") and any(ref_p in http_meta.get("path", "").lower() for ref_p in ref_paths):
                is_suspicious = True
                susp_reasons.append(f"HTTP request to KPOT exfiltration path {http_meta.get('path')}")

            if http_meta.get("method") == "POST" and "gate" in http_meta.get("path", "").lower():
                is_suspicious = True
                susp_reasons.append("Suspicious HTTP POST beacon to gate endpoint")

            if mac_src in ref_macs or mac_dst in ref_macs:
                is_suspicious = True
                susp_reasons.append("Observed suspected infected MAC 78:2b:cb:d4:a5:fe")

            pkt_dict = {
                "packet_no": idx,
                "timestamp": ts,
                "epoch": pkt_time,
                "src_ip": src_ip or "N/A",
                "dst_ip": dst_ip or "N/A",
                "protocol": proto,
                "src_port": sport,
                "dst_port": dport,
                "length": pkt_len,
                "info": info_text,
                "is_suspicious": is_suspicious,
                "suspicious_reason": "; ".join(susp_reasons) if susp_reasons else "",
                "payload_snippet": payload_str[:200] if payload_str else "",
                "dns_query": dns_q,
                "http_meta": http_meta,
                "mac_src": mac_src,
                "mac_dst": mac_dst,
                "evidence_type": "Directly Observed Evidence (PCAP)"
            }
            packets.append(pkt_dict)
            if is_suspicious:
                suspicious_packets.append(pkt_dict)

        except Exception as e:
            # Tolerant parsing to prevent crash on non-standard packets
            continue

    # Corroborate Reference IOCs against real capture
    iocs = []
    for ref in REFERENCE_IOCS:
        ioc_copy = dict(ref)
        val = ref["value"]
        count = 0
        if ref["type"].startswith("IP"):
            count = sum(1 for p in packets if p.get("src_ip") == val or p.get("dst_ip") == val)
        elif ref["type"] == "Domain Name":
            count = sum(1 for p in packets if val in p.get("dns_query", "") or val in str(p.get("http_meta", {})))
        elif ref["type"] == "URI / URL Path":
            count = sum(1 for p in packets if val in str(p.get("http_meta", {}).get("path", "")))
        elif ref["type"] == "MAC Address":
            count = sum(1 for p in packets if p.get("mac_src") == val or p.get("mac_dst") == val)
        elif ref["type"] == "Hostname":
            count = sum(1 for p in packets if val in p.get("payload_snippet", "") or val in p.get("info", ""))

        ioc_copy["match_count"] = count
        if count > 0:
            ioc_copy["validation_status"] = f"Corroborated in Uploaded Capture ({count} matches)"
        else:
            ioc_copy["validation_status"] = "Reference Indicator - Uncorroborated in Current Capture"
        iocs.append(ioc_copy)

    # Derive real timeline from suspicious packets
    timeline = []
    if suspicious_packets:
        for s_idx, sp in enumerate(suspicious_packets[:8], start=1):
            timeline.append({
                "step": s_idx,
                "stage": f"Observed Activity #{s_idx}",
                "timestamp": sp["timestamp"],
                "type": "Directly Observed Evidence",
                "headline": sp["info"][:60],
                "details": sp.get("suspicious_reason") or f"Communication between {sp['src_ip']} and {sp['dst_ip']}",
                "source_ip": sp["src_ip"],
                "dest_ip": sp["dst_ip"],
                "protocol": sp["protocol"],
                "mitre": "T1071 / T1041 (Observed)",
                "evidence_status": f"Packet #{sp['packet_no']}"
            })
    else:
        # Default entry if no matches
        timeline.append({
            "step": 1,
            "stage": "Traffic Inspection",
            "timestamp": packets[0]["timestamp"] if packets else datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            "type": "Directly Observed Evidence",
            "headline": "Uploaded Traffic Monitored",
            "details": f"Parsed {len(packets)} packets. No hardcoded case study signatures triggered.",
            "source_ip": "Network",
            "dest_ip": "All",
            "protocol": "Mixed",
            "mitre": "N/A",
            "evidence_status": "Evidence Ingested"
        })

    stats = compute_statistics(packets)
    return packets, iocs, timeline, stats

# Initialize default demo dataset on startup
def init_default_demo():
    pkts, iocs, tl, stats = generate_synthetic_demo_data()
    current_state["mode"] = "demo"
    current_state["file_name"] = "Synthetic_RIG_KPOT_Case_Study.pcap"
    current_state["file_hash"] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    current_state["file_size"] = "142.8 KB"
    current_state["upload_timestamp"] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    current_state["packets"] = pkts
    current_state["iocs"] = iocs
    current_state["timeline"] = tl
    current_state["stats"] = stats

init_default_demo()

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def get_status():
    return jsonify({
        "mode": current_state["mode"],
        "file_name": current_state["file_name"],
        "file_hash": current_state["file_hash"],
        "file_size": current_state["file_size"],
        "upload_timestamp": current_state["upload_timestamp"],
        "total_packets": len(current_state["packets"]),
        "scapy_installed": SCAPY_AVAILABLE,
        "analyst_notes": current_state["analyst_notes"]
    })

@app.route('/api/stats')
def get_stats():
    return jsonify(current_state["stats"])

@app.route('/api/packets')
def get_packets():
    # Filter parameters
    proto = request.args.get('protocol', '').strip().upper()
    src_ip = request.args.get('src_ip', '').strip()
    dst_ip = request.args.get('dst_ip', '').strip()
    suspicious_only = request.args.get('suspicious_only', '').lower() == 'true'
    search = request.args.get('search', '').lower().strip()
    limit = request.args.get('limit', 500, type=int)

    filtered = current_state["packets"]

    if proto and proto != "ALL":
        filtered = [p for p in filtered if p.get("protocol", "").upper() == proto]
    if src_ip:
        filtered = [p for p in filtered if src_ip in p.get("src_ip", "")]
    if dst_ip:
        filtered = [p for p in filtered if dst_ip in p.get("dst_ip", "")]
    if suspicious_only:
        filtered = [p for p in filtered if p.get("is_suspicious")]
    if search:
        filtered = [
            p for p in filtered if (
                search in p.get("src_ip", "").lower() or
                search in p.get("dst_ip", "").lower() or
                search in p.get("info", "").lower() or
                search in p.get("protocol", "").lower() or
                search in p.get("suspicious_reason", "").lower() or
                search in p.get("payload_snippet", "").lower()
            )
        ]

    return jsonify({
        "total_matching": len(filtered),
        "packets": filtered[:limit]
    })

@app.route('/api/iocs')
def get_iocs():
    return jsonify({
        "iocs": current_state["iocs"],
        "reference_warning": "Reference indicators must be corroborated against uploaded evidence before confirming active compromise."
    })

@app.route('/api/timeline')
def get_timeline():
    return jsonify({
        "mode": current_state["mode"],
        "timeline": current_state["timeline"],
        "attack_chain_summary": [
            {"step": 1, "name": "Compromised / Malicious Webpage", "status": "Initiation"},
            {"step": 2, "name": "RIG Exploit Kit Activity", "status": "Exploitation"},
            {"step": 3, "name": "Malware Delivery (Dropper)", "status": "Delivery"},
            {"step": 4, "name": "Suspected KPOT Stealer Activity", "status": "Execution"},
            {"step": 5, "name": "Suspicious External C2 Communication", "status": "Exfiltration"}
        ]
    })

@app.route('/api/mitre')
def get_mitre():
    return jsonify({
        "framework": MITRE_FRAMEWORK,
        "mode": current_state["mode"]
    })

@app.route('/api/upload', methods=['POST'])
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "error": "No file selected"}), 400

    if not allowed_file(file.filename):
        return jsonify({"success": False, "error": "Invalid file format. Only .pcap and .pcapng files are supported."}), 400

    filename = secure_filename(file.filename)
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(save_path)
        file_size_bytes = os.path.getsize(save_path)
        file_size_str = f"{file_size_bytes / 1024:.1f} KB" if file_size_bytes < 1024*1024 else f"{file_size_bytes / (1024*1024):.2f} MB"
        file_hash = calculate_sha256(save_path)

        # Parse PCAP
        packets, iocs, timeline, stats = parse_real_pcap(save_path)

        current_state["mode"] = "pcap"
        current_state["file_name"] = filename
        current_state["file_hash"] = file_hash
        current_state["file_size"] = file_size_str
        current_state["upload_timestamp"] = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        current_state["packets"] = packets
        current_state["iocs"] = iocs
        current_state["timeline"] = timeline
        current_state["stats"] = stats

        return jsonify({
            "success": True,
            "message": f"Successfully parsed {len(packets)} packets from {filename}.",
            "file_name": filename,
            "file_hash": file_hash,
            "file_size": file_size_str,
            "packet_count": len(packets),
            "suspicious_count": stats.get("suspicious_events", 0)
        })

    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to parse PCAP file: {str(e)}"}), 500

@app.route('/api/demo', methods=['POST'])
def load_demo():
    init_default_demo()
    return jsonify({
        "success": True,
        "message": "Synthetic demo dataset loaded successfully.",
        "mode": "demo",
        "file_name": current_state["file_name"],
        "packet_count": len(current_state["packets"])
    })

@app.route('/api/reset', methods=['POST'])
def reset_analysis():
    current_state["mode"] = "empty"
    current_state["file_name"] = "No Capture Loaded"
    current_state["file_hash"] = "N/A"
    current_state["file_size"] = "0 KB"
    current_state["packets"] = []
    current_state["iocs"] = [dict(ref, validation_status="Awaiting Capture Ingestion", match_count=0) for ref in REFERENCE_IOCS]
    current_state["timeline"] = []
    current_state["stats"] = compute_statistics([])
    return jsonify({"success": True, "message": "Analysis state reset."})

@app.route('/api/notes', methods=['POST'])
def save_notes():
    data = request.get_json() or {}
    current_state["analyst_notes"] = data.get("notes", "")
    return jsonify({"success": True, "message": "Analyst notes saved."})

@app.route('/api/export/csv')
def export_packets_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Packet_No", "Timestamp", "Source_IP", "Dest_IP", "Protocol",
        "Source_Port", "Dest_Port", "Length", "Info", "Is_Suspicious",
        "Suspicious_Reason", "DNS_Query", "Payload_Snippet"
    ])

    for p in current_state["packets"]:
        writer.writerow([
            p.get("packet_no"),
            p.get("timestamp"),
            p.get("src_ip"),
            p.get("dst_ip"),
            p.get("protocol"),
            p.get("src_port"),
            p.get("dst_port"),
            p.get("length"),
            p.get("info"),
            p.get("is_suspicious"),
            p.get("suspicious_reason"),
            p.get("dns_query"),
            p.get("payload_snippet")
        ])

    output.seek(0)
    filename = f"forensic_packets_{current_state['mode']}_{int(time.time())}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

@app.route('/api/export/iocs/csv')
def export_iocs_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Type", "Indicator_Value", "Category", "Severity", "Validation_Status", "Matches", "Description"])

    for ioc in current_state["iocs"]:
        writer.writerow([
            ioc.get("id"),
            ioc.get("type"),
            ioc.get("value"),
            ioc.get("category"),
            ioc.get("severity"),
            ioc.get("validation_status"),
            ioc.get("match_count", 0),
            ioc.get("description")
        ])

    output.seek(0)
    filename = f"forensic_iocs_{int(time.time())}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )

if __name__ == '__main__':
    print("=" * 70)
    print(" G66 NETWORK FORENSIC ANALYSIS PLATFORM")
    print(" Case Study: RIG Exploit Kit & KPOT Stealer Drive-by Infection")
    print(" Starting SOC web interface at http://127.0.0.1:5000")
    print("=" * 70)
    app.run(host='127.0.0.1', port=5000, debug=True)
