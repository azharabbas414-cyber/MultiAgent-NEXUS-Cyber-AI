"""NEXUS Cyber AI PCAP Network + Malware Intelligence.

Offline-first PCAP/PCAPNG analysis. The parser never executes recovered files.
It extracts network metadata and safe file/artifact indicators (hash, type,
size, printable strings) and can optionally query VirusTotal by SHA-256 only
when VT_API_KEY is configured. Raw files are never uploaded by NEXUS.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from collections import Counter, defaultdict
from io import BytesIO
from typing import Any

import pandas as pd
import requests
from scapy.all import ARP, IP, IPv6, TCP, UDP, Raw, rdpcap


MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_ARTIFACTS = 20


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


def _artifact_type(blob: bytes) -> tuple[str, str]:
    """Classify common file signatures without executing or parsing the file."""
    if blob.startswith(b"MZ"):
        return "PE/Windows executable", "Executable"
    if blob.startswith(b"\x7fELF"):
        return "ELF executable", "Executable"
    if blob.startswith(b"PK\x03\x04"):
        return "ZIP/Office archive", "Archive"
    if blob.startswith(b"%PDF"):
        return "PDF", "Document"
    if blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG", "Image"
    if blob.startswith(b"\xff\xd8\xff"):
        return "JPEG", "Image"
    return "Unknown binary", "Binary"


def _strings(blob: bytes, limit: int = 12) -> list[str]:
    values = re.findall(rb"[ -~]{6,}", blob[:MAX_ARTIFACT_BYTES])
    return [v.decode("utf-8", errors="replace")[:180] for v in values[:limit]]


def _extract_artifacts(packets: Any) -> list[dict[str, Any]]:
    """Find likely transferred files from TCP payloads using safe signatures.

    This is intentionally conservative. It does not execute or submit files.
    It looks for PE/ELF/archive/PDF/image signatures in reassembled payloads.
    """
    streams: dict[str, bytearray] = defaultdict(bytearray)
    meta: dict[str, dict[str, Any]] = {}

    for packet in packets:
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            continue
        src, dst = _ip_version(packet)
        if not src or not dst:
            continue
        sport, dport = int(packet[TCP].sport), int(packet[TCP].dport)
        # Keep direction because request/response direction matters when we later display evidence.
        key = f"{src}:{sport} → {dst}:{dport}"
        payload = bytes(packet[Raw].load)
        if not payload:
            continue
        if len(streams[key]) < MAX_ARTIFACT_BYTES:
            streams[key].extend(payload[: MAX_ARTIFACT_BYTES - len(streams[key])])
        meta[key] = {"source_ip": src, "destination_ip": dst, "source_port": sport, "destination_port": dport}

    artifacts: list[dict[str, Any]] = []
    signatures = (b"MZ", b"\x7fELF", b"PK\x03\x04", b"%PDF", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff")
    for flow, blob in streams.items():
        if len(artifacts) >= MAX_ARTIFACTS:
            break
        raw = bytes(blob)
        positions = [(raw.find(sig), sig) for sig in signatures]
        positions = [(p, sig) for p, sig in positions if p >= 0]
        if not positions:
            continue
        offset, _ = min(positions, key=lambda x: x[0])
        candidate = raw[offset:]
        if not candidate:
            continue
        digest = hashlib.sha256(candidate).hexdigest()
        kind, category = _artifact_type(candidate)
        artifacts.append({
            "artifact_id": f"ART-{len(artifacts)+1:03d}",
            "flow": flow,
            "source_ip": meta[flow]["source_ip"],
            "destination_ip": meta[flow]["destination_ip"],
            "source_port": meta[flow]["source_port"],
            "destination_port": meta[flow]["destination_port"],
            "type": kind,
            "category": category,
            "size": len(candidate),
            "sha256": digest,
            "strings": _strings(candidate),
            "local_assessment": "Executable artifact candidate recovered from TCP payload; exact malware identity requires signature/hash intelligence or deeper analysis.",
        })
    return artifacts


def _virustotal_lookup(sha256: str) -> dict[str, Any]:
    """Optional hash-only VirusTotal lookup. No file content is uploaded."""
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured", "message": "VT_API_KEY is not configured; no external malware reputation lookup was performed."}
    try:
        response = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            timeout=12,
        )
        if response.status_code == 404:
            return {"status": "not_found", "message": "SHA-256 was not found in VirusTotal."}
        response.raise_for_status()
        attrs = response.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        classification = attrs.get("popular_threat_classification", {}) or {}
        label = classification.get("suggested_threat_label") or classification.get("popular_threat_category")
        return {
            "status": "found",
            "reputation": stats,
            "threat_label": label or "Unknown",
            "type_description": attrs.get("type_description"),
            "meaningful_name": attrs.get("meaningful_name"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "message": "Hash-only reputation lookup completed.",
        }
    except Exception as exc:
        return {"status": "error", "message": f"Threat-intelligence lookup failed: {type(exc).__name__}."}


def _malware_summary(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    results = []
    for artifact in artifacts:
        vt = _virustotal_lookup(artifact["sha256"])
        artifact = dict(artifact)
        artifact["threat_intelligence"] = vt
        results.append(artifact)
    confirmed = [a for a in results if a.get("threat_intelligence", {}).get("status") == "found" and a.get("threat_intelligence", {}).get("threat_label") not in (None, "Unknown")]
    executable_candidates = [a for a in results if a.get("category") == "Executable"]
    if confirmed:
        status = "Threat intelligence match"
    elif executable_candidates:
        status = "Executable artifact candidate; malware identity not confirmed"
    elif results:
        status = "Suspicious artifact candidate; malware identity not confirmed"
    else:
        status = "No recoverable file artifact identified"
    return {
        "status": status,
        "artifacts": results,
        "artifact_count": len(results),
        "executable_count": len(executable_candidates),
        "confirmed_count": len(confirmed),
        "exact_malware_names": sorted({a["threat_intelligence"].get("threat_label") for a in confirmed if a["threat_intelligence"].get("threat_label")}),
        "note": "Exact malware naming is only reported when artifact evidence or hash intelligence supports it. NEXUS never guesses a family name.",
    }


def analyze_pcap(data: bytes, filename: str = "capture.pcap") -> tuple[pd.DataFrame, dict[str, Any]]:
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
    artifacts = _extract_artifacts(packets)
    malware = _malware_summary(artifacts)
    if not df.empty:
        df.attrs["nexus_dataset_type"] = "pcap"
        df.attrs["pcap_filename"] = filename
        df.attrs["pcap_malware"] = malware

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
        "malware_analysis": malware,
    }
    return df, summary
