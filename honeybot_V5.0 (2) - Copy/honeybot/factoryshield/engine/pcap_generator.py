"""
FactoryShield: Automated Incident PCAP Forensic Evidence Generator
Synthesizes valid PCAP network packet captures for incidents to enable
deep forensic analysis in Wireshark.
"""
import io
import time
from datetime import datetime
from typing import Dict, Any, List

from scapy.all import Ether, IP, TCP, Raw, wrpcap
from factoryshield.enterprise.company import get_host_by_name

# Default IP fallback mappings
DEFAULT_HOST_IPS = {
    "WS-MGMT-01": "192.168.10.11",
    "WS-ENG-01": "192.168.10.15",
    "WS-PROD-01": "192.168.10.22",
    "WS-HR-01": "192.168.10.35",
    "WS-IT-01": "192.168.10.5",
    "cad-srv01": "192.168.20.10",
    "cad-repo01": "192.168.20.15",
    "db-prod01": "192.168.30.10",
    "plc-sim01": "192.168.30.20",
    "hmi-prod01": "192.168.30.5",
    "sec-mon01": "192.168.99.10"
}

def resolve_host_ip(hostname: str) -> str:
    cleaned = hostname.split(".")[0].strip()
    host_obj = get_host_by_name(cleaned)
    if host_obj:
        return host_obj.ip
    return DEFAULT_HOST_IPS.get(cleaned, "192.168.10.100")

def determine_service_port(target_host: str, resource: str, service_name: str) -> int:
    tgt = target_host.lower()
    res = resource.lower()
    srv = service_name.lower()

    if "502" in srv or "modbus" in res or "plc" in tgt:
        return 502
    if "8088" in srv or "cad-srv01" in tgt or "vault" in res:
        return 8088
    if "8080" in srv or "hmi" in tgt:
        return 8080
    if "21" in srv or "ftp" in srv or "repo" in tgt:
        return 21
    if "2222" in srv or "ssh" in srv:
        return 2222
    if "db" in tgt or "mysql" in res:
        return 3306
    return 8080

def build_incident_pcap_bytes(incident: Dict[str, Any]) -> bytes:
    """
    Builds a full Wireshark-compatible PCAP byte stream for the given incident.
    """
    forensics = incident.get("forensics", {})
    timeline = forensics.get("events_timeline", [])
    actor = incident.get("actor", "attacker")
    packets = []

    base_time = time.time() - len(timeline) * 2

    sport = 49200
    for idx, ev in enumerate(timeline):
        src_host = ev.get("source_host", "WS-ENG-01")
        tgt_host = ev.get("target_host", "cad-srv01")
        resource = ev.get("resource", "/")
        action = ev.get("action", "GET")
        details = ev.get("details", "")

        src_ip = resolve_host_ip(src_host)
        dst_ip = resolve_host_ip(tgt_host)
        dport = determine_service_port(tgt_host, resource, incident.get("service_name", ""))
        sport += 1

        seq_c = 1000 + (idx * 500)
        seq_s = 5000 + (idx * 500)
        t_offset = base_time + (idx * 0.5)

        # 1. TCP 3-Way Handshake (SYN)
        p1 = Ether(src="00:1A:2B:3C:4D:5E", dst="00:5E:4D:3C:2B:1A") / \
             IP(src=src_ip, dst=dst_ip) / \
             TCP(sport=sport, dport=dport, flags="S", seq=seq_c)
        p1.time = t_offset
        packets.append(p1)

        # 2. TCP SYN-ACK
        p2 = Ether(src="00:5E:4D:3C:2B:1A", dst="00:1A:2B:3C:4D:5E") / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1)
        p2.time = t_offset + 0.002
        packets.append(p2)

        # 3. TCP ACK
        p3 = Ether(src="00:1A:2B:3C:4D:5E", dst="00:5E:4D:3C:2B:1A") / \
             IP(src=src_ip, dst=dst_ip) / \
             TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1)
        p3.time = t_offset + 0.003
        packets.append(p3)

        # 4. Application Payload (HTTP / Modbus / FTP / SSH)
        if dport == 502:
            # Modbus TCP Read Holding Registers
            # MBAP (7 bytes) + Function 0x03 (4 bytes)
            mbap = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x6c\x00\x02"
            app_req = Raw(load=mbap)
            app_resp = Raw(load=b"\x00\x01\x00\x00\x00\x07\x01\x03\x04\xde\xad\x00\x01")
        elif dport == 21:
            app_req = Raw(load=f"USER {actor}\r\nRETR {resource}\r\n".encode("utf-8"))
            app_resp = Raw(load=b"550 Decoy File Access Flagged by Security\r\n")
        elif dport == 2222:
            app_req = Raw(load=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu\r\n")
            app_resp = Raw(load=b"SSH-2.0-FactoryShield_Decoy_SSH_Trap\r\n")
        else:
            # HTTP Request
            http_msg = (
                f"{action.upper()} {resource} HTTP/1.1\r\n"
                f"Host: {tgt_host}.jim.corp\r\n"
                f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                f"X-FactoryShield-Actor: {actor}\r\n"
                f"Accept: */*\r\n\r\n"
            ).encode("utf-8")
            app_req = Raw(load=http_msg)
            app_resp = Raw(load=b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nServer: JIM-Industrial/5.1\r\n\r\n[DECOY_CANARY_PAYLOAD]")

        # 5. Client Request Packet
        p4 = Ether(src="00:1A:2B:3C:4D:5E", dst="00:5E:4D:3C:2B:1A") / \
             IP(src=src_ip, dst=dst_ip) / \
             TCP(sport=sport, dport=dport, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / \
             app_req
        p4.time = t_offset + 0.010
        packets.append(p4)

        # 6. Server Response Packet
        p5 = Ether(src="00:5E:4D:3C:2B:1A", dst="00:1A:2B:3C:4D:5E") / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=dport, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 1 + len(bytes(app_req))) / \
             app_resp
        p5.time = t_offset + 0.015
        packets.append(p5)

        # 7. TCP FIN Teardown
        p6 = Ether(src="00:1A:2B:3C:4D:5E", dst="00:5E:4D:3C:2B:1A") / \
             IP(src=src_ip, dst=dst_ip) / \
             TCP(sport=sport, dport=dport, flags="FA", seq=seq_c + 1 + len(bytes(app_req)), ack=seq_s + 1 + len(bytes(app_resp)))
        p6.time = t_offset + 0.020
        packets.append(p6)

        p7 = Ether(src="00:5E:4D:3C:2B:1A", dst="00:1A:2B:3C:4D:5E") / \
             IP(src=dst_ip, dst=src_ip) / \
             TCP(sport=dport, dport=sport, flags="A", seq=seq_s + 1 + len(bytes(app_resp)), ack=seq_c + 2 + len(bytes(app_req)))
        p7.time = t_offset + 0.022
        packets.append(p7)

    # Write to temporary file and read bytes
    import tempfile
    import os
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    tmp_path = tmp.name
    tmp.close()
    try:
        wrpcap(tmp_path, packets)
        with open(tmp_path, "rb") as f:
            pcap_bytes = f.read()
        return pcap_bytes
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
