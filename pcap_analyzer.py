"""NEXUS Cyber AI PCAP Network Intelligence.

Offline-only PCAP/PCAPNG analysis. No packets are transmitted and no live
network action is performed. The parser converts packet captures into a
compact, analytics-friendly dataframe plus summary metadata.
"""
from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from io import BytesIO
from typing import Any

import pandas as pd
from scapy.all import ARP, IP, IPv6, TCP, UDP, rdpcap


def _ip_version(packet: Any) -> tuple[str | None, str | None]:
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    if packet.haslayer(ARP):
        return packet[ARP].psrc or None, packet[ARP].pdst or None
    return None, None


def _private(value: str | None) -> bool | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return None


def tcp_flag_label(flags: Any) -> str:
    """Return human-readable TCP flag combinations."""
    raw = str(flags or "")
    names = []
    mapping = [("S", "SYN"), ("A", "ACK"), ("F", "FIN"), ("R", "RST"), ("P", "PSH"), ("U", "URG"), ("E", "ECE"), ("C", "CWR")]
    for short, label in mapping:
        if short in raw:
            names.append(label)
    return " + ".join(names) if names else "TCP"


def _protocol(packet: Any) -> str:
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IP) or packet.haslayer(IPv6):
        return "IP"
    return str(getattr(packet, "name", "Other"))


def _service(port: int | None) -> str:
    return {
        53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 443: "HTTPS",
        123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
        445: "SMB", 1900: "SSDP", 22: "SSH", 21: "FTP", 25: "SMTP",
        3389: "RDP", 161: "SNMP", 5060: "SIP",
    }.get(int(port or 0), "Other")


def analyze_pcap(data: bytes, filename: str = "capture.pcap") -> tuple[pd.DataFrame, dict[str, Any]]:
    """Parse an offline PCAP/PCAPNG byte stream into packet rows and summary."""
    packets = rdpcap(BytesIO(data))
    rows: list[dict[str, Any]] = []
    flows: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    flags: Counter[str] = Counter()
    services: Counter[str] = Counter()
    src_counts: Counter[str] = Counter()
    dst_counts: Counter[str] = Counter()

    for index, packet in enumerate(packets, start=1):
        src, dst = _ip_version(packet)
        protocol = _protocol(packet)
        sport = dport = None
        flag = ""
        flag_label = ""
        if packet.haslayer(TCP):
            sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
            flag = str(packet[TCP].flags)
            flag_label = tcp_flag_label(flag)
            flags[flag_label] += 1
        elif packet.haslayer(UDP):
            sport, dport = int(packet[UDP].sport), int(packet[UDP].dport)

        service = _service(dport) if dport else "Other"
        if service == "Other" and sport:
            service = _service(sport)
        if service != "Other":
            services[service] += 1

        protocol_counts[protocol] += 1
        if src:
            src_counts[src] += 1
        if dst:
            dst_counts[dst] += 1

        flow = f"{src or '-'}:{sport or '-'} → {dst or '-'}:{dport or '-'} / {protocol}"
        if src and dst:
            flows[flow] += 1

        ts = float(packet.time) if hasattr(packet, "time") else None
        rows.append({
            "timestamp": pd.to_datetime(ts, unit="s", errors="coerce") if ts is not None else pd.NaT,
            "event_id": f"PCAP-{index:06d}",
            "event_type": f"TCP {flag_label}" if protocol == "TCP" and flag_label else protocol,
            "source_ip": src,
            "destination_ip": dst,
            "protocol": protocol,
            "source_port": sport,
            "destination_port": dport,
            "service": service,
            "tcp_flags": flag_label,
            "packet_length": int(len(packet)),
            "direction": "Internal → External" if _private(src) and _private(dst) is False else ("External → Internal" if _private(src) is False and _private(dst) else "Other"),
            "flow": flow,
            "incident_id": "PCAP-NETWORK-ANALYSIS",
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df.attrs["nexus_dataset_type"] = "pcap"
        df.attrs["pcap_filename"] = filename

    summary = {
        "dataset_type": "pcap",
        "filename": filename,
        "packets": len(packets),
        "protocol_counts": dict(protocol_counts),
        "tcp_flags": dict(flags),
        "services": dict(services),
        "top_source_ips": dict(src_counts.most_common(10)),
        "top_destination_ips": dict(dst_counts.most_common(10)),
        "top_flows": dict(flows.most_common(10)),
        "unique_source_ips": len(src_counts),
        "unique_destination_ips": len(dst_counts),
        "unique_flows": len(flows),
        "capture_start": str(df["timestamp"].min()) if not df.empty else None,
        "capture_end": str(df["timestamp"].max()) if not df.empty else None,
    }
    return df, summary
