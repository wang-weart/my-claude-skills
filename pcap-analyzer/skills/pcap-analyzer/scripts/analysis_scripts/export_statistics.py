#!/usr/bin/env python3
"""Compute detailed traffic statistics from a network capture file.

Produces protocol hierarchy, packet size distribution, inter-packet timing,
TCP flag analysis, TTL distribution, and transport-layer breakdown.

Output:
  {name}_statistics.json - comprehensive traffic statistics
"""

import sys
import os
import json
import math
from collections import defaultdict, Counter
from datetime import datetime

from scapy.all import *


# TCP flag bit names
TCP_FLAGS = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR",
}

# Common TCP flag combinations
TCP_FLAG_COMBOS = {
    0x02: "SYN",
    0x12: "SYN-ACK",
    0x10: "ACK",
    0x18: "PSH-ACK",
    0x11: "FIN-ACK",
    0x14: "RST-ACK",
    0x04: "RST",
    0x01: "FIN",
    0x19: "FIN-PSH-ACK",
    0x00: "NULL",
    0x29: "FIN-URG-PSH",
    0x3F: "ALL-FLAGS",
}


def parse_env():
    """Read configuration from environment variables."""
    capture_file = os.environ.get("PCAP_CAPTURE_FILE", "")
    if not capture_file and len(sys.argv) > 1:
        capture_file = sys.argv[1]
    if not capture_file:
        print("Error: No capture file specified", file=sys.stderr)
        sys.exit(1)

    output_dir = os.environ.get("PCAP_OUTPUT_DIR", ".")
    bpf_filter = os.environ.get("PCAP_BPF_FILTER", "")
    verbose = os.environ.get("PCAP_VERBOSE", "false").lower() == "true"

    name = os.path.splitext(os.path.basename(capture_file))[0]

    return capture_file, output_dir, bpf_filter, verbose, name


def load_packets(capture_file, bpf_filter, verbose):
    """Load packets from capture file, applying optional BPF filter."""
    print(f"Loading {capture_file}...")
    try:
        packets = rdpcap(capture_file)
    except Exception as e:
        print(f"Error reading capture file: {e}", file=sys.stderr)
        sys.exit(1)

    total = len(packets)
    print(f"Loaded {total} packets")

    if bpf_filter:
        try:
            filtered = [p for p in packets if p.haslayer(IP)]
            if "tcp" in bpf_filter.lower():
                filtered = [p for p in filtered if p.haslayer(TCP)]
            elif "udp" in bpf_filter.lower():
                filtered = [p for p in filtered if p.haslayer(UDP)]
            packets = PacketList(filtered)
            print(f"After filtering: {len(packets)} packets (from {total})")
        except Exception as e:
            if verbose:
                print(f"BPF filter note: {e}", file=sys.stderr)

    return packets


def flags_to_str(flags_int):
    """Convert TCP flags integer to a human-readable string."""
    if flags_int in TCP_FLAG_COMBOS:
        return TCP_FLAG_COMBOS[flags_int]
    parts = []
    for bit_char, name in TCP_FLAGS.items():
        bit_val = {
            "F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
            "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80,
        }[bit_char]
        if flags_int & bit_val:
            parts.append(name)
    return "-".join(parts) if parts else f"0x{flags_int:02x}"


def compute_histogram(values, bucket_count=20):
    """Compute a histogram with evenly spaced buckets."""
    if not values:
        return []
    min_val = min(values)
    max_val = max(values)
    if min_val == max_val:
        return [{"range_start": min_val, "range_end": max_val, "count": len(values)}]

    bucket_size = (max_val - min_val) / bucket_count
    buckets = [0] * bucket_count

    for v in values:
        idx = int((v - min_val) / bucket_size)
        if idx >= bucket_count:
            idx = bucket_count - 1
        buckets[idx] += 1

    result = []
    for i, count in enumerate(buckets):
        result.append({
            "range_start": round(min_val + i * bucket_size, 2),
            "range_end": round(min_val + (i + 1) * bucket_size, 2),
            "count": count,
        })
    return result


def compute_percentile(sorted_values, p):
    """Compute the p-th percentile from a sorted list."""
    if not sorted_values:
        return 0
    k = (len(sorted_values) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_values[int(k)]
    return sorted_values[f] * (c - k) + sorted_values[c] * (k - f)


def build_protocol_hierarchy(packets, verbose):
    """Build a nested protocol hierarchy tree."""
    # We track chains like Ethernet > IP > TCP > HTTP
    hierarchy = {}

    total = len(packets)
    for i, pkt in enumerate(packets):
        if verbose and (i + 1) % 10000 == 0:
            print(f"  Protocol hierarchy: packet {i+1}/{total}...")

        chain = []
        layer = pkt
        while layer:
            layer_name = layer.__class__.__name__
            # Normalize some layer names
            if layer_name == "Padding":
                break
            if layer_name == "Raw":
                # Try to identify application protocol
                if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ",
                                           b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/1.")):
                        layer_name = "HTTP"
                    elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                        layer_name = "TLS"
                    elif pkt[TCP].dport == 22 or pkt[TCP].sport == 22:
                        layer_name = "SSH"
                    else:
                        layer_name = "Data"
                elif pkt.haslayer(UDP) and pkt.haslayer(Raw):
                    if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                        layer_name = "DNS"
                    else:
                        layer_name = "Data"
                else:
                    layer_name = "Data"
            chain.append(layer_name)
            layer = layer.payload if hasattr(layer, "payload") and layer.payload else None

        # Insert chain into hierarchy tree
        node = hierarchy
        for proto in chain:
            if proto not in node:
                node[proto] = {"_count": 0, "_bytes": 0}
            node[proto]["_count"] += 1
            node[proto]["_bytes"] += len(pkt)
            node = node[proto]

    return hierarchy


def format_hierarchy(node, depth=0):
    """Convert the raw hierarchy dict into a cleaner JSON-friendly structure."""
    result = []
    for key, val in sorted(node.items()):
        if key.startswith("_"):
            continue
        entry = {
            "protocol": key,
            "packet_count": val.get("_count", 0),
            "byte_count": val.get("_bytes", 0),
        }
        children = format_hierarchy(val, depth + 1)
        if children:
            entry["children"] = children
        result.append(entry)
    return result


def main():
    capture_file, output_dir, bpf_filter, verbose, name = parse_env()
    output_path = os.path.join(output_dir, f"{name}_statistics.json")

    packets = load_packets(capture_file, bpf_filter, verbose)
    total = len(packets)

    if total == 0:
        print("No packets to analyze.")
        result = {
            "capture_file": os.path.basename(capture_file),
            "total_packets": 0,
            "protocol_hierarchy": [],
            "packet_sizes": {},
            "timing": {},
            "tcp_flags": {},
            "ip_ttl": {},
            "transport": {},
        }
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"Wrote empty statistics to {output_path}")
        return

    # ---- Protocol Hierarchy ----
    print("Computing protocol hierarchy...")
    raw_hierarchy = build_protocol_hierarchy(packets, verbose)
    protocol_hierarchy = format_hierarchy(raw_hierarchy)

    # ---- Packet Sizes ----
    print("Computing packet size distribution...")
    sizes = [len(pkt) for pkt in packets]
    sorted_sizes = sorted(sizes)

    packet_sizes = {
        "min": min(sizes),
        "max": max(sizes),
        "avg": round(sum(sizes) / len(sizes), 2),
        "median": compute_percentile(sorted_sizes, 50),
        "p95": compute_percentile(sorted_sizes, 95),
        "p99": compute_percentile(sorted_sizes, 99),
        "total_bytes": sum(sizes),
        "histogram": compute_histogram(sizes, bucket_count=20),
    }

    # ---- Timing ----
    print("Computing timing statistics...")
    timestamps = sorted([float(pkt.time) for pkt in packets])
    inter_packet_gaps = []
    for i in range(1, len(timestamps)):
        gap = timestamps[i] - timestamps[i - 1]
        inter_packet_gaps.append(gap)

    capture_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.0

    # Packets per second over time (1-second buckets)
    pps_buckets = []
    if capture_duration > 0:
        bucket_duration = max(1.0, capture_duration / min(100, max(1, int(capture_duration))))
        bucket_start = timestamps[0]
        bucket_count = 0
        for ts in timestamps:
            if ts < bucket_start + bucket_duration:
                bucket_count += 1
            else:
                pps_buckets.append({
                    "time_offset": round(bucket_start - timestamps[0], 3),
                    "packets_per_second": round(bucket_count / bucket_duration, 2),
                })
                bucket_start += bucket_duration
                # Skip ahead if there's a big gap
                while ts >= bucket_start + bucket_duration:
                    pps_buckets.append({
                        "time_offset": round(bucket_start - timestamps[0], 3),
                        "packets_per_second": 0.0,
                    })
                    bucket_start += bucket_duration
                bucket_count = 1
        # Final bucket
        if bucket_count > 0:
            pps_buckets.append({
                "time_offset": round(bucket_start - timestamps[0], 3),
                "packets_per_second": round(bucket_count / bucket_duration, 2),
            })

    timing = {
        "capture_start": datetime.utcfromtimestamp(timestamps[0]).isoformat() + "Z",
        "capture_end": datetime.utcfromtimestamp(timestamps[-1]).isoformat() + "Z",
        "capture_duration_seconds": round(capture_duration, 6),
        "total_packets": total,
        "avg_packets_per_second": round(total / capture_duration, 2) if capture_duration > 0 else total,
    }

    if inter_packet_gaps:
        sorted_gaps = sorted(inter_packet_gaps)
        timing["inter_packet_gap"] = {
            "min_seconds": round(min(inter_packet_gaps), 9),
            "max_seconds": round(max(inter_packet_gaps), 9),
            "avg_seconds": round(sum(inter_packet_gaps) / len(inter_packet_gaps), 9),
            "median_seconds": round(compute_percentile(sorted_gaps, 50), 9),
        }
    else:
        timing["inter_packet_gap"] = {
            "min_seconds": 0,
            "max_seconds": 0,
            "avg_seconds": 0,
            "median_seconds": 0,
        }

    timing["packets_per_second_over_time"] = pps_buckets

    # ---- TCP Flags ----
    print("Computing TCP flag distribution...")
    tcp_flag_counts = Counter()
    tcp_flag_individual = Counter()
    tcp_packets_total = 0

    for pkt in packets:
        if not pkt.haslayer(TCP):
            continue
        tcp_packets_total += 1
        flags_int = int(pkt[TCP].flags)
        flag_name = flags_to_str(flags_int)
        tcp_flag_counts[flag_name] += 1

        # Count individual flags
        for bit_char, flag_name_ind in TCP_FLAGS.items():
            bit_val = {
                "F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08,
                "A": 0x10, "U": 0x20, "E": 0x40, "C": 0x80,
            }[bit_char]
            if flags_int & bit_val:
                tcp_flag_individual[flag_name_ind] += 1

    tcp_flags = {
        "total_tcp_packets": tcp_packets_total,
        "flag_combinations": [
            {"flags": name, "count": count, "percentage": round(100.0 * count / tcp_packets_total, 2)}
            for name, count in tcp_flag_counts.most_common()
        ] if tcp_packets_total > 0 else [],
        "individual_flags": [
            {"flag": name, "count": count, "percentage": round(100.0 * count / tcp_packets_total, 2)}
            for name, count in tcp_flag_individual.most_common()
        ] if tcp_packets_total > 0 else [],
    }

    # ---- IP TTL Distribution ----
    print("Computing TTL distribution...")
    ttl_counts = Counter()
    ttl_values = []

    for pkt in packets:
        if pkt.haslayer(IP):
            ttl = pkt[IP].ttl
            ttl_counts[ttl] += 1
            ttl_values.append(ttl)

    # Group TTLs by common OS defaults for fingerprinting hints
    os_hints = {
        "Linux/Android (64)": 0,
        "Windows (128)": 0,
        "macOS/iOS (64)": 0,
        "Cisco/Network (255)": 0,
        "Other": 0,
    }
    for ttl, count in ttl_counts.items():
        if 1 <= ttl <= 64:
            os_hints["Linux/Android (64)"] += count
        elif 65 <= ttl <= 128:
            os_hints["Windows (128)"] += count
        elif ttl == 255:
            os_hints["Cisco/Network (255)"] += count
        else:
            os_hints["Other"] += count

    ip_ttl = {
        "total_ip_packets": len(ttl_values),
        "unique_ttl_values": len(ttl_counts),
        "distribution": [
            {"ttl": ttl, "count": count}
            for ttl, count in sorted(ttl_counts.items())
        ],
        "os_fingerprint_hints": [
            {"category": cat, "packet_count": count, "percentage": round(100.0 * count / len(ttl_values), 2) if ttl_values else 0}
            for cat, count in os_hints.items()
            if count > 0
        ],
    }

    if ttl_values:
        sorted_ttl = sorted(ttl_values)
        ip_ttl["min"] = min(ttl_values)
        ip_ttl["max"] = max(ttl_values)
        ip_ttl["avg"] = round(sum(ttl_values) / len(ttl_values), 2)
        ip_ttl["median"] = compute_percentile(sorted_ttl, 50)

    # ---- Transport Breakdown ----
    print("Computing transport breakdown...")
    transport_counts = Counter()
    transport_bytes = Counter()

    for pkt in packets:
        if pkt.haslayer(TCP):
            transport_counts["TCP"] += 1
            transport_bytes["TCP"] += len(pkt)
        elif pkt.haslayer(UDP):
            transport_counts["UDP"] += 1
            transport_bytes["UDP"] += len(pkt)
        elif pkt.haslayer(ICMP):
            transport_counts["ICMP"] += 1
            transport_bytes["ICMP"] += len(pkt)
        elif pkt.haslayer(ICMPv6Unknown) or pkt.haslayer(IPv6):
            # ICMPv6 or IPv6 without TCP/UDP
            if pkt.haslayer(IPv6) and not pkt.haslayer(TCP) and not pkt.haslayer(UDP):
                transport_counts["IPv6-Other"] += 1
                transport_bytes["IPv6-Other"] += len(pkt)
        elif pkt.haslayer(ARP):
            transport_counts["ARP"] += 1
            transport_bytes["ARP"] += len(pkt)
        elif pkt.haslayer(IP):
            proto_num = pkt[IP].proto
            proto_name = f"IP-Proto-{proto_num}"
            transport_counts[proto_name] += 1
            transport_bytes[proto_name] += len(pkt)
        else:
            transport_counts["Other"] += 1
            transport_bytes["Other"] += len(pkt)

    transport = {
        "breakdown": [
            {
                "protocol": proto,
                "packet_count": count,
                "packet_percentage": round(100.0 * count / total, 2),
                "byte_count": transport_bytes[proto],
                "byte_percentage": round(100.0 * transport_bytes[proto] / sum(sizes), 2) if sum(sizes) > 0 else 0,
            }
            for proto, count in transport_counts.most_common()
        ],
    }

    # ---- Assemble Result ----
    result = {
        "capture_file": os.path.basename(capture_file),
        "total_packets": total,
        "total_bytes": sum(sizes),
        "protocol_hierarchy": protocol_hierarchy,
        "packet_sizes": packet_sizes,
        "timing": timing,
        "tcp_flags": tcp_flags,
        "ip_ttl": ip_ttl,
        "transport": transport,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"Wrote statistics to {output_path}")
    print(f"  Packets: {total}")
    print(f"  Duration: {capture_duration:.3f}s")
    print(f"  Protocols: {len(protocol_hierarchy)} top-level")
    print(f"  TCP flag combinations: {len(tcp_flag_counts)}")
    print(f"  Unique TTL values: {len(ttl_counts)}")
    print(f"  Transport protocols: {len(transport_counts)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
