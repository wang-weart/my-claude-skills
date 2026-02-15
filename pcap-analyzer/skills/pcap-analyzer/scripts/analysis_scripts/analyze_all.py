#!/usr/bin/env python3
"""Comprehensive first-pass analysis of network capture files.

Produces:
  {name}_summary.txt       - Capture overview (file size, packets, time range, duration)
  {name}_protocols.json    - Protocol distribution by layer
  {name}_endpoints.json    - Top talkers by packet count and byte count
  {name}_conversations.json - Top conversations (IP pairs)
  {name}_interesting.txt   - Notable findings categorized by type
"""

import sys
import os
import json
import time
from collections import Counter, defaultdict
from datetime import datetime

from scapy.all import *


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def get_output_path(name, suffix):
    output_dir = os.environ.get("PCAP_OUTPUT_DIR", ".")
    return os.path.join(output_dir, f"{name}{suffix}")


def is_verbose():
    return os.environ.get("PCAP_VERBOSE", "false").lower() == "true"


def get_bpf_filter():
    return os.environ.get("PCAP_BPF_FILTER", "")


# ---------------------------------------------------------------------------
# Packet loading
# ---------------------------------------------------------------------------

def load_packets(capture_file):
    """Load packets from capture file, applying BPF filter if set."""
    bpf = get_bpf_filter()
    if bpf:
        print(f"  Applying BPF filter: {bpf}")
        try:
            packets = sniff(offline=capture_file, filter=bpf)
        except Exception as e:
            print(f"  Warning: BPF filter failed ({e}), loading without filter")
            packets = rdpcap(capture_file)
    else:
        packets = rdpcap(capture_file)
    return packets


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def export_summary(packets, capture_file, name):
    path = get_output_path(name, "_summary.txt")
    print(f"  Exporting summary to {os.path.basename(path)}")

    file_size = os.path.getsize(capture_file)
    pkt_count = len(packets)

    # Time range
    timestamps = [float(pkt.time) for pkt in packets if hasattr(pkt, "time")]
    if timestamps:
        first_ts = min(timestamps)
        last_ts = max(timestamps)
        duration = last_ts - first_ts
        first_dt = datetime.fromtimestamp(first_ts).strftime("%Y-%m-%d %H:%M:%S.%f")
        last_dt = datetime.fromtimestamp(last_ts).strftime("%Y-%m-%d %H:%M:%S.%f")
    else:
        first_dt = last_dt = "N/A"
        duration = 0.0

    # Byte counts
    total_bytes = sum(len(pkt) for pkt in packets)
    if pkt_count > 0:
        avg_pkt_size = total_bytes / pkt_count
        min_pkt_size = min(len(pkt) for pkt in packets)
        max_pkt_size = max(len(pkt) for pkt in packets)
    else:
        avg_pkt_size = min_pkt_size = max_pkt_size = 0

    with open(path, "w") as f:
        f.write("Network Capture Analysis Summary\n")
        f.write("================================\n\n")
        f.write(f"File: {os.path.basename(capture_file)}\n")
        f.write(f"File size: {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)\n")
        f.write(f"Packet count: {pkt_count:,}\n")
        f.write(f"Total bytes on wire: {total_bytes:,}\n\n")

        f.write("Time Range:\n")
        f.write(f"  First packet: {first_dt}\n")
        f.write(f"  Last packet:  {last_dt}\n")
        f.write(f"  Duration:     {duration:.3f} seconds\n\n")

        f.write("Packet Sizes:\n")
        f.write(f"  Average: {avg_pkt_size:.1f} bytes\n")
        f.write(f"  Min:     {min_pkt_size} bytes\n")
        f.write(f"  Max:     {max_pkt_size} bytes\n\n")

        if duration > 0:
            f.write("Rates:\n")
            f.write(f"  Packets/sec: {pkt_count / duration:.1f}\n")
            f.write(f"  Bytes/sec:   {total_bytes / duration:.1f}\n")
            f.write(f"  Bits/sec:    {(total_bytes * 8) / duration:.1f}\n\n")

        # Data-link layer info
        if pkt_count > 0:
            first_pkt = packets[0]
            f.write("Link Layer:\n")
            f.write(f"  Type: {first_pkt.__class__.__name__}\n")

    print(f"  Summary written ({pkt_count:,} packets, {duration:.1f}s duration)")


# ---------------------------------------------------------------------------
# Protocol distribution
# ---------------------------------------------------------------------------

def export_protocols(packets, name):
    path = get_output_path(name, "_protocols.json")
    print(f"  Exporting protocol distribution to {os.path.basename(path)}")

    layer_counts = Counter()
    transport_counts = Counter()
    app_counts = Counter()

    for pkt in packets:
        # Walk all layers in the packet
        layer = pkt
        while layer:
            layer_name = layer.__class__.__name__
            if layer_name == "NoPayload":
                break
            layer_counts[layer_name] += 1

            # Categorise
            if layer_name in ("TCP", "UDP", "ICMP", "ICMPv6", "SCTP"):
                transport_counts[layer_name] += 1
            elif layer_name in ("DNS", "HTTP", "HTTPRequest", "HTTPResponse",
                                "TLS", "NTP", "DHCP", "BOOTP", "SNMP",
                                "STP", "HSRP", "VRRP", "BGP", "OSPF",
                                "Raw"):
                app_counts[layer_name] += 1

            layer = layer.payload

    result = {
        "all_layers": dict(layer_counts.most_common()),
        "transport": dict(transport_counts.most_common()),
        "application": dict(app_counts.most_common()),
        "total_packets": len(packets),
    }

    with open(path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"  Found {len(layer_counts)} distinct protocol layers")


# ---------------------------------------------------------------------------
# Endpoints (top talkers)
# ---------------------------------------------------------------------------

def export_endpoints(packets, name):
    path = get_output_path(name, "_endpoints.json")
    print(f"  Exporting endpoints to {os.path.basename(path)}")

    ip_pkt_count = Counter()
    ip_byte_count = Counter()
    mac_pkt_count = Counter()
    port_count = Counter()

    for pkt in packets:
        pkt_len = len(pkt)

        # Ethernet MACs
        if pkt.haslayer(Ether):
            mac_pkt_count[pkt[Ether].src] += 1
            mac_pkt_count[pkt[Ether].dst] += 1

        # IP addresses
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            ip_pkt_count[src] += 1
            ip_pkt_count[dst] += 1
            ip_byte_count[src] += pkt_len
            ip_byte_count[dst] += pkt_len
        elif pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
            ip_pkt_count[src] += 1
            ip_pkt_count[dst] += 1
            ip_byte_count[src] += pkt_len
            ip_byte_count[dst] += pkt_len

        # Ports
        if pkt.haslayer(TCP):
            port_count[pkt[TCP].sport] += 1
            port_count[pkt[TCP].dport] += 1
        elif pkt.haslayer(UDP):
            port_count[pkt[UDP].sport] += 1
            port_count[pkt[UDP].dport] += 1

    # Build top-N lists
    top_n = 50
    result = {
        "top_ips_by_packets": [
            {"ip": ip, "packets": cnt}
            for ip, cnt in ip_pkt_count.most_common(top_n)
        ],
        "top_ips_by_bytes": [
            {"ip": ip, "bytes": cnt}
            for ip, cnt in ip_byte_count.most_common(top_n)
        ],
        "top_macs_by_packets": [
            {"mac": mac, "packets": cnt}
            for mac, cnt in mac_pkt_count.most_common(top_n)
        ],
        "top_ports": [
            {"port": port, "packets": cnt}
            for port, cnt in port_count.most_common(top_n)
        ],
        "unique_ips": len(ip_pkt_count),
        "unique_macs": len(mac_pkt_count),
        "unique_ports": len(port_count),
    }

    with open(path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"  Found {len(ip_pkt_count)} unique IPs, "
          f"{len(mac_pkt_count)} unique MACs, "
          f"{len(port_count)} unique ports")


# ---------------------------------------------------------------------------
# Conversations (IP pairs)
# ---------------------------------------------------------------------------

def export_conversations(packets, name):
    path = get_output_path(name, "_conversations.json")
    print(f"  Exporting conversations to {os.path.basename(path)}")

    convos = defaultdict(lambda: {"packets": 0, "bytes": 0, "protocols": set()})

    for pkt in packets:
        src = dst = None
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src = pkt[IPv6].src
            dst = pkt[IPv6].dst
        else:
            continue

        # Normalise key so A<->B is one conversation
        key = tuple(sorted([src, dst]))
        convos[key]["packets"] += 1
        convos[key]["bytes"] += len(pkt)

        if pkt.haslayer(TCP):
            convos[key]["protocols"].add("TCP")
        if pkt.haslayer(UDP):
            convos[key]["protocols"].add("UDP")
        if pkt.haslayer(ICMP):
            convos[key]["protocols"].add("ICMP")

    # Sort by packet count descending
    sorted_convos = sorted(convos.items(), key=lambda x: x[1]["packets"], reverse=True)

    result = []
    for (ip_a, ip_b), info in sorted_convos[:100]:
        result.append({
            "ip_a": ip_a,
            "ip_b": ip_b,
            "packets": info["packets"],
            "bytes": info["bytes"],
            "protocols": sorted(info["protocols"]),
        })

    with open(path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"  Found {len(convos)} unique conversations")


# ---------------------------------------------------------------------------
# Interesting / notable findings
# ---------------------------------------------------------------------------

CLEARTEXT_PORTS = {
    21: "FTP",
    23: "Telnet",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    513: "rlogin",
    514: "rsh/syslog",
    1080: "SOCKS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    11211: "Memcached",
    27017: "MongoDB",
}

ENCRYPTED_PORTS = {443, 465, 636, 853, 993, 995, 8443}

SUSPICIOUS_TLDS = {
    "top", "xyz", "club", "work", "date", "racing", "win", "bid",
    "stream", "gdn", "loan", "download", "review", "accountant",
    "click", "link", "trade", "cricket", "faith", "party", "science",
    "tk", "ml", "ga", "cf", "gq",
}

WELL_KNOWN_PORTS = set(range(0, 1024))


def export_interesting(packets, name):
    path = get_output_path(name, "_interesting.txt")
    print(f"  Analyzing for interesting patterns...")

    findings = {
        "CLEARTEXT_PROTOCOLS": [],
        "UNUSUAL_PORTS": [],
        "LARGE_TRANSFERS": [],
        "SUSPICIOUS_DNS": [],
        "ENCRYPTED_TRAFFIC": [],
        "POTENTIAL_TUNNELING": [],
    }

    # Track per-conversation bytes for large-transfer detection
    convo_bytes = Counter()
    cleartext_seen = set()
    unusual_ports_seen = set()
    encrypted_seen = set()
    dns_queries = []

    for pkt in packets:
        src_ip = dst_ip = None
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        sport = dport = None
        proto = None
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            proto = "TCP"
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            proto = "UDP"

        if src_ip and dst_ip:
            key = tuple(sorted([src_ip, dst_ip]))
            convo_bytes[key] += len(pkt)

        # Cleartext protocols
        if dport and dport in CLEARTEXT_PORTS:
            tag = (CLEARTEXT_PORTS[dport], dport, dst_ip)
            if tag not in cleartext_seen:
                cleartext_seen.add(tag)
                findings["CLEARTEXT_PROTOCOLS"].append(
                    f"{CLEARTEXT_PORTS[dport]} (port {dport}) to {dst_ip}"
                )

        if sport and sport in CLEARTEXT_PORTS:
            tag = (CLEARTEXT_PORTS[sport], sport, src_ip)
            if tag not in cleartext_seen:
                cleartext_seen.add(tag)
                findings["CLEARTEXT_PROTOCOLS"].append(
                    f"{CLEARTEXT_PORTS[sport]} (port {sport}) from {src_ip}"
                )

        # Encrypted traffic
        if dport and dport in ENCRYPTED_PORTS:
            tag = (dport, dst_ip)
            if tag not in encrypted_seen:
                encrypted_seen.add(tag)
                findings["ENCRYPTED_TRAFFIC"].append(
                    f"Port {dport} to {dst_ip}"
                )

        # Unusual high ports for server-like traffic (non-ephemeral destination)
        if dport and proto:
            if dport not in WELL_KNOWN_PORTS and dport not in CLEARTEXT_PORTS and dport not in ENCRYPTED_PORTS:
                if 1024 < dport < 49152:
                    tag = (proto, dport)
                    if tag not in unusual_ports_seen:
                        unusual_ports_seen.add(tag)
                        findings["UNUSUAL_PORTS"].append(
                            f"{proto}/{dport} ({src_ip} -> {dst_ip})"
                        )

        # DNS analysis for suspicious TLDs
        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                dns_queries.append(qname)
                parts = qname.split(".")
                if len(parts) >= 2:
                    tld = parts[-1].lower()
                    if tld in SUSPICIOUS_TLDS:
                        findings["SUSPICIOUS_DNS"].append(
                            f"{qname} (TLD: .{tld})"
                        )
                # Check for very long domain names (possible tunneling)
                if len(qname) > 60:
                    findings["POTENTIAL_TUNNELING"].append(
                        f"Long DNS name ({len(qname)} chars): {qname[:80]}..."
                    )
            except Exception:
                pass

        # DNS with many labels can indicate tunneling
        if pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
                labels = qname.split(".")
                if len(labels) > 6:
                    findings["POTENTIAL_TUNNELING"].append(
                        f"Many DNS labels ({len(labels)}): {qname[:80]}"
                    )
            except Exception:
                pass

        # Large ICMP payloads can indicate tunneling
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
            payload_len = len(pkt[Raw].load)
            if payload_len > 100:
                findings["POTENTIAL_TUNNELING"].append(
                    f"Large ICMP payload ({payload_len} bytes): {src_ip} -> {dst_ip}"
                )

    # Large transfers (conversations with > 1 MB)
    for (ip_a, ip_b), byte_count in convo_bytes.most_common(20):
        if byte_count > 1_000_000:
            findings["LARGE_TRANSFERS"].append(
                f"{ip_a} <-> {ip_b}: {byte_count:,} bytes "
                f"({byte_count / (1024*1024):.1f} MB)"
            )

    # Deduplicate potential tunneling (can be noisy)
    seen_tunneling = set()
    deduped = []
    for item in findings["POTENTIAL_TUNNELING"]:
        key = item[:60]
        if key not in seen_tunneling:
            seen_tunneling.add(key)
            deduped.append(item)
    findings["POTENTIAL_TUNNELING"] = deduped[:50]

    # Deduplicate unusual ports (cap at 50)
    findings["UNUSUAL_PORTS"] = findings["UNUSUAL_PORTS"][:50]
    # Deduplicate suspicious DNS
    seen_dns = set()
    deduped_dns = []
    for item in findings["SUSPICIOUS_DNS"]:
        if item not in seen_dns:
            seen_dns.add(item)
            deduped_dns.append(item)
    findings["SUSPICIOUS_DNS"] = deduped_dns[:100]

    # Write findings
    with open(path, "w") as f:
        f.write("Interesting Findings in Network Capture\n")
        f.write("=======================================\n\n")

        total_findings = sum(len(v) for v in findings.values())
        f.write(f"Total findings: {total_findings}\n\n")

        for category, items in findings.items():
            f.write(f"[{category}] ({len(items)} findings)\n")
            if items:
                for item in items:
                    f.write(f"  - {item}\n")
            else:
                f.write("  (none)\n")
            f.write("\n")

    print(f"  Found {total_findings} interesting items across "
          f"{sum(1 for v in findings.values() if v)} categories")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_all.py <capture_file>", file=sys.stderr)
        sys.exit(1)

    capture_file = sys.argv[1]
    name = os.path.splitext(os.path.basename(capture_file))[0]

    print(f"=== Comprehensive capture analysis ===")
    print(f"Capture: {capture_file}")
    print(f"Output prefix: {name}")

    if not os.path.isfile(capture_file):
        print(f"Error: File not found: {capture_file}", file=sys.stderr)
        sys.exit(1)

    start_time = time.time()

    try:
        print(f"  Loading packets...")
        packets = load_packets(capture_file)
        print(f"  Loaded {len(packets):,} packets")
    except Exception as e:
        print(f"Error loading capture file: {e}", file=sys.stderr)
        sys.exit(1)

    if len(packets) == 0:
        print("Warning: Capture file contains no packets")

    try:
        export_summary(packets, capture_file, name)
    except Exception as e:
        print(f"  Error in summary export: {e}", file=sys.stderr)

    try:
        export_protocols(packets, name)
    except Exception as e:
        print(f"  Error in protocol export: {e}", file=sys.stderr)

    try:
        export_endpoints(packets, name)
    except Exception as e:
        print(f"  Error in endpoints export: {e}", file=sys.stderr)

    try:
        export_conversations(packets, name)
    except Exception as e:
        print(f"  Error in conversations export: {e}", file=sys.stderr)

    try:
        export_interesting(packets, name)
    except Exception as e:
        print(f"  Error in interesting-findings export: {e}", file=sys.stderr)

    elapsed = time.time() - start_time
    print(f"\n=== Analysis complete ({elapsed:.1f}s) ===")


if __name__ == "__main__":
    main()
