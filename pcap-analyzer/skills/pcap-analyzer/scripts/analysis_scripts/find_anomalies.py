#!/usr/bin/env python3
"""Detect suspicious network patterns in packet captures for forensics/RE.

Analyzes pcap files for beaconing (C2 indicators), port scanning, data
exfiltration, unusual protocols, cleartext sensitive data, and TLS anomalies.
"""

import sys
import os
import json
import math
import hashlib
from collections import defaultdict
from datetime import datetime

from scapy.all import *


def get_config():
    """Read configuration from environment variables."""
    if len(sys.argv) < 2:
        print("Usage: find_anomalies.py <capture_file>", file=sys.stderr)
        sys.exit(1)

    capture_file = sys.argv[1]
    name = os.path.splitext(os.path.basename(capture_file))[0]
    output_dir = os.environ.get("PCAP_OUTPUT_DIR", ".")
    bpf_filter = os.environ.get("PCAP_BPF_FILTER", "")
    verbose = os.environ.get("PCAP_VERBOSE", "false").lower() == "true"
    timeout = os.environ.get("PCAP_TIMEOUT", "")

    return {
        "capture_file": capture_file,
        "name": name,
        "output_dir": output_dir,
        "bpf_filter": bpf_filter,
        "verbose": verbose,
        "timeout": int(timeout) if timeout else None,
    }


def load_packets(capture_file, bpf_filter=""):
    """Load packets from capture file, applying BPF filter if set."""
    print(f"Loading {capture_file}...", file=sys.stderr)
    file_size = os.path.getsize(capture_file)
    print(f"  File size: {file_size / (1024*1024):.1f} MB", file=sys.stderr)

    packets = rdpcap(capture_file)
    print(f"  Loaded {len(packets)} packets", file=sys.stderr)

    if bpf_filter:
        try:
            from scapy.arch import compile_filter
            # Try native BPF filtering
            filtered = [p for p in packets if p.haslayer(IP)]
            print(f"  BPF filter set: '{bpf_filter}' (applying IP-layer filter)", file=sys.stderr)
            packets = filtered
        except Exception:
            print(f"  Warning: Could not apply BPF filter '{bpf_filter}', using all packets", file=sys.stderr)

    return packets


def compute_stats(values):
    """Compute mean, standard deviation, and coefficient of variation."""
    if len(values) < 2:
        return 0.0, 0.0, float("inf")
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
    stddev = math.sqrt(variance)
    cv = stddev / mean if mean > 0 else float("inf")
    return mean, stddev, cv


def compute_entropy(data):
    """Compute Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def detect_beaconing(packets, verbose=False):
    """Detect regular-interval connections that may indicate C2 beaconing.

    Groups connections by (src_ip, dst_ip, dst_port), computes inter-arrival
    times, and flags those with coefficient of variation < 0.3.
    """
    print("  Detecting beaconing patterns...", file=sys.stderr)
    connections = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            dst_port = pkt[TCP].dport
            ts = float(pkt.time)
            connections[(src_ip, dst_ip, dst_port)].append(ts)

    beacons = []
    for (src_ip, dst_ip, dst_port), timestamps in connections.items():
        if len(timestamps) < 5:
            continue

        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        # Filter out zero or near-zero intervals (bursts within same connection)
        intervals = [iv for iv in intervals if iv > 0.5]

        if len(intervals) < 4:
            continue

        mean, stddev, cv = compute_stats(intervals)

        if cv < 0.3 and mean > 1.0:
            beacons.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "interval_avg": round(mean, 3),
                "interval_stddev": round(stddev, 3),
                "coefficient_of_variation": round(cv, 4),
                "packet_count": len(timestamps),
                "duration_seconds": round(timestamps[-1] - timestamps[0], 2),
            })

            if verbose:
                print(f"    Beacon: {src_ip} -> {dst_ip}:{dst_port} "
                      f"interval={mean:.1f}s cv={cv:.3f} pkts={len(timestamps)}", file=sys.stderr)

    beacons.sort(key=lambda x: x["coefficient_of_variation"])
    return beacons


def detect_port_scanning(packets, threshold=10, verbose=False):
    """Detect single source hitting many ports on the same destination.

    Threshold: >10 unique ports from same source to same destination.
    """
    print("  Detecting port scanning...", file=sys.stderr)
    scan_map = defaultdict(lambda: {"ports": set(), "syn_count": 0, "connect_count": 0, "flags": set()})

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            dst_port = pkt[TCP].dport
            flags = pkt[TCP].flags

            key = (src_ip, dst_ip)
            scan_map[key]["ports"].add(dst_port)

            flag_str = str(flags)
            scan_map[key]["flags"].add(flag_str)
            if "S" in flag_str and "A" not in flag_str:
                scan_map[key]["syn_count"] += 1
            if "S" in flag_str and "A" in flag_str:
                scan_map[key]["connect_count"] += 1

    scans = []
    for (src_ip, dst_ip), info in scan_map.items():
        if len(info["ports"]) > threshold:
            # Determine scan type
            if info["syn_count"] > len(info["ports"]) * 0.5:
                scan_type = "SYN scan"
            elif info["connect_count"] > 0:
                scan_type = "connect scan"
            else:
                scan_type = "unknown"

            ports_list = sorted(info["ports"])
            scans.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ports_scanned": len(ports_list),
                "port_list": ports_list[:100],  # Cap display at 100
                "scan_type": scan_type,
                "tcp_flags_seen": sorted(info["flags"]),
            })

            if verbose:
                print(f"    Scan: {src_ip} -> {dst_ip}: {len(ports_list)} ports ({scan_type})", file=sys.stderr)

    scans.sort(key=lambda x: x["ports_scanned"], reverse=True)
    return scans


def detect_data_exfiltration(packets, verbose=False):
    """Detect large outbound transfers and DNS tunneling.

    DNS tunneling: flag queries where subdomain labels are >30 chars or have
    high entropy (>3.5 bits/char).
    """
    print("  Detecting data exfiltration indicators...", file=sys.stderr)
    findings = []

    # Track bytes per connection for large transfers
    transfer_map = defaultdict(lambda: {"bytes": 0, "packets": 0, "first_ts": None, "last_ts": None})
    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            dst_port = pkt[TCP].dport
            payload_len = len(pkt[Raw].load)
            ts = float(pkt.time)

            key = (src_ip, dst_ip, dst_port)
            transfer_map[key]["bytes"] += payload_len
            transfer_map[key]["packets"] += 1
            if transfer_map[key]["first_ts"] is None:
                transfer_map[key]["first_ts"] = ts
            transfer_map[key]["last_ts"] = ts

    # Flag large outbound transfers (>1MB)
    large_threshold = 1024 * 1024
    for (src_ip, dst_ip, dst_port), info in transfer_map.items():
        if info["bytes"] > large_threshold:
            duration = (info["last_ts"] - info["first_ts"]) if info["first_ts"] and info["last_ts"] else 0
            findings.append({
                "type": "large_transfer",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "bytes": info["bytes"],
                "packets": info["packets"],
                "duration_seconds": round(duration, 2),
                "description": f"Large outbound transfer: {info['bytes']/(1024*1024):.2f} MB to {dst_ip}:{dst_port}",
            })

    # DNS tunneling detection
    dns_queries = defaultdict(list)
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
                dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
                ts = float(pkt.time)

                # Split into labels and check subdomain lengths
                labels = qname.split(".")
                # Check non-TLD labels (exclude last 2 labels as domain.tld)
                subdomain_labels = labels[:-2] if len(labels) > 2 else []

                for label in subdomain_labels:
                    if len(label) > 30:
                        entropy = compute_entropy(label)
                        findings.append({
                            "type": "dns_tunneling",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "bytes": len(qname),
                            "description": f"Suspicious DNS query: long subdomain label ({len(label)} chars, entropy={entropy:.2f})",
                            "query": qname[:200],
                            "label_length": len(label),
                            "label_entropy": round(entropy, 3),
                            "timestamp": ts,
                        })
                        break
                    elif len(label) > 15:
                        entropy = compute_entropy(label)
                        if entropy > 3.5:
                            findings.append({
                                "type": "dns_tunneling",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "bytes": len(qname),
                                "description": f"Suspicious DNS query: high entropy subdomain ({entropy:.2f} bits/char)",
                                "query": qname[:200],
                                "label_length": len(label),
                                "label_entropy": round(entropy, 3),
                                "timestamp": ts,
                            })
                            break
            except Exception:
                continue

    if verbose and findings:
        for f in findings:
            print(f"    Exfil: {f['type']} - {f['description'][:80]}", file=sys.stderr)

    return findings


def detect_unusual_protocols(packets, verbose=False):
    """Detect non-standard port usage, ICMP tunneling, DNS over non-53.

    Checks for:
    - Known protocols on unexpected ports
    - ICMP packets with large payloads (possible tunnel)
    - DNS traffic on non-standard ports
    """
    print("  Detecting unusual protocol usage...", file=sys.stderr)
    findings = []

    # Standard port mappings
    standard_ports = {
        80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
        110: "POP3", 143: "IMAP", 53: "DNS", 3389: "RDP", 23: "Telnet",
        8080: "HTTP-alt", 8443: "HTTPS-alt",
    }

    # Track HTTP on non-standard ports
    http_signatures = [b"HTTP/1.", b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD "]
    ssh_signature = b"SSH-"
    dns_non53 = set()

    for pkt in packets:
        # ICMP with large payloads
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
            payload_len = len(pkt[Raw].load)
            if payload_len > 64:
                src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
                dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"
                findings.append({
                    "type": "icmp_tunnel_suspect",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "payload_size": payload_len,
                    "icmp_type": pkt[ICMP].type,
                    "description": f"ICMP packet with large payload ({payload_len} bytes) - possible tunnel",
                    "timestamp": float(pkt.time),
                })

        # DNS over non-53
        if pkt.haslayer(DNS) and pkt.haslayer(IP):
            if pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                if dport != 53 and sport != 53:
                    key = (pkt[IP].src, pkt[IP].dst, dport)
                    if key not in dns_non53:
                        dns_non53.add(key)
                        findings.append({
                            "type": "dns_non_standard_port",
                            "src_ip": pkt[IP].src,
                            "dst_ip": pkt[IP].dst,
                            "port": dport,
                            "description": f"DNS traffic on non-standard port {dport}",
                            "timestamp": float(pkt.time),
                        })
            elif pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                if dport != 53:
                    key = (pkt[IP].src, pkt[IP].dst, dport)
                    if key not in dns_non53:
                        dns_non53.add(key)
                        findings.append({
                            "type": "dns_over_tcp_non_standard",
                            "src_ip": pkt[IP].src,
                            "dst_ip": pkt[IP].dst,
                            "port": dport,
                            "description": f"DNS over TCP on non-standard port {dport}",
                            "timestamp": float(pkt.time),
                        })

        # HTTP/SSH on non-standard ports
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport
            payload = pkt[Raw].load[:50]

            # HTTP on non-standard port
            if dport not in (80, 8080, 8000, 8888, 443, 8443):
                for sig in http_signatures:
                    if payload.startswith(sig):
                        findings.append({
                            "type": "http_non_standard_port",
                            "src_ip": pkt[IP].src,
                            "dst_ip": pkt[IP].dst,
                            "port": dport,
                            "description": f"HTTP traffic detected on non-standard port {dport}",
                            "timestamp": float(pkt.time),
                        })
                        break

            # SSH on non-standard port
            if dport != 22 and sport != 22 and payload.startswith(ssh_signature):
                findings.append({
                    "type": "ssh_non_standard_port",
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "port": dport if not payload.startswith(ssh_signature) else sport,
                    "description": f"SSH traffic detected on non-standard port",
                    "timestamp": float(pkt.time),
                })

    # Deduplicate by limiting same type/src/dst combinations
    seen = set()
    deduped = []
    for f in findings:
        key = (f["type"], f.get("src_ip"), f.get("dst_ip"), f.get("port", ""))
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    if verbose:
        for f in deduped:
            print(f"    Protocol: {f['type']} - {f['description'][:80]}", file=sys.stderr)

    return deduped


def detect_cleartext_sensitive(packets, verbose=False):
    """Detect unencrypted protocols carrying potentially sensitive data.

    Flags: FTP, Telnet, HTTP Basic Auth, SMTP with credentials.
    """
    print("  Detecting cleartext sensitive protocols...", file=sys.stderr)
    findings = []
    seen_connections = set()

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        ts = float(pkt.time)

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            continue

        payload_lower = payload.lower()

        # FTP cleartext
        if dport == 21 or sport == 21:
            conn_key = ("ftp", src_ip, dst_ip)
            if conn_key not in seen_connections:
                if any(cmd in payload_lower for cmd in ["user ", "pass ", "230 ", "530 "]):
                    seen_connections.add(conn_key)
                    findings.append({
                        "type": "ftp_cleartext",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": dport,
                        "description": "FTP cleartext authentication detected",
                        "timestamp": ts,
                    })

        # Telnet cleartext
        if dport == 23 or sport == 23:
            conn_key = ("telnet", src_ip, dst_ip)
            if conn_key not in seen_connections:
                seen_connections.add(conn_key)
                findings.append({
                    "type": "telnet_cleartext",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": dport,
                    "description": "Telnet cleartext session detected",
                    "timestamp": ts,
                })

        # HTTP Basic/Digest Auth
        if dport in (80, 8080, 8000, 8888) or sport in (80, 8080, 8000, 8888):
            if "authorization:" in payload_lower:
                conn_key = ("http_auth", src_ip, dst_ip, dport)
                if conn_key not in seen_connections:
                    seen_connections.add(conn_key)
                    auth_type = "Basic" if "basic " in payload_lower else "Digest" if "digest " in payload_lower else "Other"
                    findings.append({
                        "type": "http_auth_cleartext",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": dport,
                        "auth_type": auth_type,
                        "description": f"HTTP {auth_type} authentication over cleartext",
                        "timestamp": ts,
                    })

        # SMTP cleartext
        if dport in (25, 587) or sport in (25, 587):
            if "auth " in payload_lower or "auth login" in payload_lower:
                conn_key = ("smtp_auth", src_ip, dst_ip)
                if conn_key not in seen_connections:
                    seen_connections.add(conn_key)
                    findings.append({
                        "type": "smtp_auth_cleartext",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "port": dport,
                        "description": "SMTP authentication over cleartext",
                        "timestamp": ts,
                    })

    if verbose:
        for f in findings:
            print(f"    Cleartext: {f['type']} {f['src_ip']}->{f['dst_ip']}", file=sys.stderr)

    return findings


def detect_tls_anomalies(packets, verbose=False):
    """Detect TLS anomalies: non-standard ports, unusual handshakes.

    Note: Deep TLS inspection (cert validation, cipher analysis) requires
    parsing TLS records. We detect TLS by looking for the handshake signature.
    """
    print("  Detecting TLS anomalies...", file=sys.stderr)
    findings = []
    seen = set()

    # TLS content types: 0x16 = handshake, 0x17 = application data
    # TLS versions: 0x0301 = TLS 1.0, 0x0302 = TLS 1.1, 0x0303 = TLS 1.2, 0x0304 = TLS 1.3
    standard_tls_ports = {443, 8443, 993, 995, 465, 636, 989, 990}

    tls_version_names = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        payload = pkt[Raw].load
        if len(payload) < 6:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        ts = float(pkt.time)

        # Check for TLS record header: content_type(1) + version(2) + length(2)
        content_type = payload[0]
        if content_type not in (0x14, 0x15, 0x16, 0x17):
            continue

        version = (payload[1] << 8) | payload[2]
        if version not in tls_version_names:
            continue

        # This looks like TLS traffic
        version_name = tls_version_names.get(version, f"unknown(0x{version:04x})")

        # TLS on non-standard port
        if dport not in standard_tls_ports and sport not in standard_tls_ports:
            key = ("tls_nonstandard", src_ip, dst_ip, dport)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "type": "tls_non_standard_port",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": dport,
                    "tls_version": version_name,
                    "description": f"TLS ({version_name}) on non-standard port {dport}",
                    "timestamp": ts,
                })

        # Deprecated TLS versions
        if version in (0x0300, 0x0301, 0x0302):
            key = ("tls_deprecated", src_ip, dst_ip, version)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "type": "tls_deprecated_version",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "port": dport,
                    "tls_version": version_name,
                    "description": f"Deprecated TLS version in use: {version_name}",
                    "timestamp": ts,
                })

        # Parse ClientHello for cipher suites and SNI
        if content_type == 0x16 and len(payload) > 43:
            # handshake_type at payload[5]
            handshake_type = payload[5]
            if handshake_type == 0x01:  # ClientHello
                try:
                    # Skip: record header(5) + handshake header(4) + client_version(2) + random(32)
                    offset = 5 + 4 + 2 + 32
                    if offset >= len(payload):
                        continue

                    # Session ID length
                    session_id_len = payload[offset]
                    offset += 1 + session_id_len

                    if offset + 2 > len(payload):
                        continue

                    # Cipher suites length
                    cipher_suites_len = (payload[offset] << 8) | payload[offset + 1]
                    offset += 2

                    if offset + cipher_suites_len > len(payload):
                        continue

                    # Extract cipher suite IDs
                    cipher_suites = []
                    for i in range(0, cipher_suites_len, 2):
                        if offset + i + 1 < len(payload):
                            cs = (payload[offset + i] << 8) | payload[offset + i + 1]
                            cipher_suites.append(f"0x{cs:04x}")

                    # Check for weak cipher suites (NULL, EXPORT, RC4, DES)
                    weak_ciphers = {
                        "0x0000": "TLS_NULL_WITH_NULL_NULL",
                        "0x0001": "TLS_RSA_WITH_NULL_MD5",
                        "0x0002": "TLS_RSA_WITH_NULL_SHA",
                        "0x0004": "TLS_RSA_WITH_RC4_128_MD5",
                        "0x0005": "TLS_RSA_WITH_RC4_128_SHA",
                        "0x000a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                    }

                    offered_weak = []
                    for cs in cipher_suites:
                        if cs in weak_ciphers:
                            offered_weak.append(f"{cs} ({weak_ciphers[cs]})")

                    if offered_weak:
                        key = ("tls_weak_cipher", src_ip, dst_ip)
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "type": "tls_weak_cipher_offered",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "port": dport,
                                "weak_ciphers": offered_weak,
                                "total_ciphers_offered": len(cipher_suites),
                                "description": f"Client offering {len(offered_weak)} weak cipher suites",
                                "timestamp": ts,
                            })
                except Exception:
                    continue

            # ServerHello - check for weak cipher selection
            elif handshake_type == 0x02:  # ServerHello
                try:
                    offset = 5 + 4 + 2 + 32
                    if offset >= len(payload):
                        continue

                    session_id_len = payload[offset]
                    offset += 1 + session_id_len

                    if offset + 2 > len(payload):
                        continue

                    selected_cipher = (payload[offset] << 8) | payload[offset + 1]
                    cs_hex = f"0x{selected_cipher:04x}"

                    weak_ciphers = {
                        "0x0000", "0x0001", "0x0002", "0x0004", "0x0005", "0x000a",
                    }

                    if cs_hex in weak_ciphers:
                        key = ("tls_weak_selected", src_ip, dst_ip)
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "type": "tls_weak_cipher_selected",
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "port": sport,
                                "selected_cipher": cs_hex,
                                "description": f"Server selected weak cipher suite {cs_hex}",
                                "timestamp": ts,
                            })
                except Exception:
                    continue

    if verbose:
        for f in findings:
            print(f"    TLS: {f['type']} - {f['description'][:80]}", file=sys.stderr)

    return findings


def main():
    config = get_config()

    try:
        packets = load_packets(config["capture_file"], config["bpf_filter"])
    except Exception as e:
        print(f"Error loading capture file: {e}", file=sys.stderr)
        sys.exit(1)

    if len(packets) == 0:
        print("No packets found in capture file.", file=sys.stderr)
        sys.exit(1)

    print(f"Analyzing {len(packets)} packets for anomalies...", file=sys.stderr)

    result = {
        "capture_file": os.path.basename(config["capture_file"]),
        "total_packets": len(packets),
        "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
        "beaconing": [],
        "port_scanning": [],
        "data_exfiltration": [],
        "unusual_protocols": [],
        "cleartext_sensitive": [],
        "tls_anomalies": [],
    }

    try:
        result["beaconing"] = detect_beaconing(packets, config["verbose"])
    except Exception as e:
        print(f"  Warning: Beaconing detection failed: {e}", file=sys.stderr)

    try:
        result["port_scanning"] = detect_port_scanning(packets, verbose=config["verbose"])
    except Exception as e:
        print(f"  Warning: Port scan detection failed: {e}", file=sys.stderr)

    try:
        result["data_exfiltration"] = detect_data_exfiltration(packets, config["verbose"])
    except Exception as e:
        print(f"  Warning: Data exfiltration detection failed: {e}", file=sys.stderr)

    try:
        result["unusual_protocols"] = detect_unusual_protocols(packets, config["verbose"])
    except Exception as e:
        print(f"  Warning: Unusual protocol detection failed: {e}", file=sys.stderr)

    try:
        result["cleartext_sensitive"] = detect_cleartext_sensitive(packets, config["verbose"])
    except Exception as e:
        print(f"  Warning: Cleartext detection failed: {e}", file=sys.stderr)

    try:
        result["tls_anomalies"] = detect_tls_anomalies(packets, config["verbose"])
    except Exception as e:
        print(f"  Warning: TLS anomaly detection failed: {e}", file=sys.stderr)

    # Summary
    total_findings = sum(len(result[k]) for k in [
        "beaconing", "port_scanning", "data_exfiltration",
        "unusual_protocols", "cleartext_sensitive", "tls_anomalies"
    ])

    result["summary"] = {
        "total_findings": total_findings,
        "beaconing_count": len(result["beaconing"]),
        "port_scanning_count": len(result["port_scanning"]),
        "data_exfiltration_count": len(result["data_exfiltration"]),
        "unusual_protocols_count": len(result["unusual_protocols"]),
        "cleartext_sensitive_count": len(result["cleartext_sensitive"]),
        "tls_anomalies_count": len(result["tls_anomalies"]),
    }

    # Write output
    output_path = os.path.join(config["output_dir"], f"{config['name']}_anomalies.json")
    os.makedirs(config["output_dir"], exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\nResults:", file=sys.stderr)
    print(f"  Beaconing patterns:     {len(result['beaconing'])}", file=sys.stderr)
    print(f"  Port scans:             {len(result['port_scanning'])}", file=sys.stderr)
    print(f"  Data exfiltration:      {len(result['data_exfiltration'])}", file=sys.stderr)
    print(f"  Unusual protocols:      {len(result['unusual_protocols'])}", file=sys.stderr)
    print(f"  Cleartext sensitive:    {len(result['cleartext_sensitive'])}", file=sys.stderr)
    print(f"  TLS anomalies:          {len(result['tls_anomalies'])}", file=sys.stderr)
    print(f"  Total findings:         {total_findings}", file=sys.stderr)
    print(f"Output: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
