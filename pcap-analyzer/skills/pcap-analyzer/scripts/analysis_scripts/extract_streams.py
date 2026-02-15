#!/usr/bin/env python3
"""TCP/UDP stream reassembly and extraction.

Reassembles TCP and UDP streams from a capture file, writing metadata
and raw stream data to disk.

Produces:
  {name}_streams.json          - Stream metadata (endpoints, protocol, sizes, duration)
  {name}_stream_{n}.bin        - Raw data for each stream (capped at 1 MB)

Optional arguments:
  --host <ip>          Filter to streams involving this IP
  --port <port>        Filter to streams involving this port
  --max-streams <n>    Maximum streams to extract (default: 100)
"""

import sys
import os
import json
import time
import argparse
from collections import defaultdict, OrderedDict
from datetime import datetime

from scapy.all import *


# ---------------------------------------------------------------------------
# Environment helpers
# ---------------------------------------------------------------------------

def get_output_path(name, suffix):
    output_dir = os.environ.get("PCAP_OUTPUT_DIR", ".")
    return os.path.join(output_dir, f"{name}{suffix}")


def get_output_dir():
    return os.environ.get("PCAP_OUTPUT_DIR", ".")


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
# Stream key helpers
# ---------------------------------------------------------------------------

def tcp_stream_key(pkt):
    """Return a normalised TCP stream key (sorted endpoints)."""
    if not pkt.haslayer(TCP):
        return None
    ip_layer = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
    else:
        return None

    src = (ip_layer.src, pkt[TCP].sport)
    dst = (ip_layer.dst, pkt[TCP].dport)
    # Normalise: smaller endpoint first
    if src <= dst:
        return ("TCP", src, dst)
    else:
        return ("TCP", dst, src)


def udp_stream_key(pkt):
    """Return a normalised UDP stream key (sorted endpoints)."""
    if not pkt.haslayer(UDP):
        return None
    ip_layer = None
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
    else:
        return None

    src = (ip_layer.src, pkt[UDP].sport)
    dst = (ip_layer.dst, pkt[UDP].dport)
    if src <= dst:
        return ("UDP", src, dst)
    else:
        return ("UDP", dst, src)


# ---------------------------------------------------------------------------
# Stream tracking
# ---------------------------------------------------------------------------

MAX_STREAM_BYTES = 1 * 1024 * 1024  # 1 MB per stream


class StreamTracker:
    """Tracks packets belonging to a single TCP or UDP stream."""

    def __init__(self, proto, endpoint_a, endpoint_b):
        self.proto = proto
        self.endpoint_a = endpoint_a  # (ip, port)
        self.endpoint_b = endpoint_b  # (ip, port)
        self.packets_a_to_b = 0
        self.packets_b_to_a = 0
        self.bytes_a_to_b = 0
        self.bytes_b_to_a = 0
        self.first_seen = None
        self.last_seen = None
        # Ordered payload data: list of (direction, bytes)
        self.payload_chunks = []
        self.total_payload_bytes = 0
        self.tcp_flags_seen = set()

    def add_packet(self, pkt, src_endpoint):
        """Add a packet to this stream."""
        ts = float(pkt.time) if hasattr(pkt, "time") else 0

        if self.first_seen is None or ts < self.first_seen:
            self.first_seen = ts
        if self.last_seen is None or ts > self.last_seen:
            self.last_seen = ts

        # Determine direction
        if src_endpoint == self.endpoint_a:
            direction = "a_to_b"
            self.packets_a_to_b += 1
            self.bytes_a_to_b += len(pkt)
        else:
            direction = "b_to_a"
            self.packets_b_to_a += 1
            self.bytes_b_to_a += len(pkt)

        # TCP flags
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags:
                self.tcp_flags_seen.add(str(flags))

        # Extract payload
        if self.total_payload_bytes < MAX_STREAM_BYTES:
            payload = b""
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
            elif self.proto == "UDP" and pkt.haslayer(UDP):
                # For UDP, the payload after UDP header
                udp_payload = bytes(pkt[UDP].payload)
                if udp_payload:
                    payload = udp_payload

            if payload:
                remaining = MAX_STREAM_BYTES - self.total_payload_bytes
                chunk = payload[:remaining]
                self.payload_chunks.append((direction, chunk))
                self.total_payload_bytes += len(chunk)

    @property
    def total_packets(self):
        return self.packets_a_to_b + self.packets_b_to_a

    @property
    def total_bytes(self):
        return self.bytes_a_to_b + self.bytes_b_to_a

    @property
    def duration(self):
        if self.first_seen and self.last_seen:
            return self.last_seen - self.first_seen
        return 0.0

    def get_raw_data(self):
        """Return concatenated payload bytes."""
        return b"".join(chunk for _, chunk in self.payload_chunks)

    def to_metadata(self, stream_index):
        """Return a JSON-serialisable metadata dict."""
        meta = {
            "stream_index": stream_index,
            "protocol": self.proto,
            "endpoint_a": {
                "ip": self.endpoint_a[0],
                "port": self.endpoint_a[1],
            },
            "endpoint_b": {
                "ip": self.endpoint_b[0],
                "port": self.endpoint_b[1],
            },
            "packets": {
                "total": self.total_packets,
                "a_to_b": self.packets_a_to_b,
                "b_to_a": self.packets_b_to_a,
            },
            "bytes": {
                "total": self.total_bytes,
                "a_to_b": self.bytes_a_to_b,
                "b_to_a": self.bytes_b_to_a,
            },
            "payload_bytes": self.total_payload_bytes,
            "duration_seconds": round(self.duration, 6),
        }

        if self.first_seen:
            meta["first_seen"] = datetime.fromtimestamp(
                self.first_seen
            ).strftime("%Y-%m-%d %H:%M:%S.%f")
        if self.last_seen:
            meta["last_seen"] = datetime.fromtimestamp(
                self.last_seen
            ).strftime("%Y-%m-%d %H:%M:%S.%f")

        if self.tcp_flags_seen:
            meta["tcp_flags_seen"] = sorted(self.tcp_flags_seen)

        return meta


# ---------------------------------------------------------------------------
# Stream filtering
# ---------------------------------------------------------------------------

def matches_filter(stream, host_filter=None, port_filter=None):
    """Check if a stream matches the optional host/port filters."""
    if host_filter:
        if (stream.endpoint_a[0] != host_filter and
                stream.endpoint_b[0] != host_filter):
            return False

    if port_filter:
        port_filter = int(port_filter)
        if (stream.endpoint_a[1] != port_filter and
                stream.endpoint_b[1] != port_filter):
            return False

    return True


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------

def extract_streams(packets, name, host_filter=None, port_filter=None,
                    max_streams=100):
    """Group packets into streams and write output files."""

    streams = OrderedDict()  # key -> StreamTracker
    verbose = is_verbose()

    print(f"  Grouping packets into streams...")

    for i, pkt in enumerate(packets):
        if verbose and (i + 1) % 10000 == 0:
            print(f"    Processed {i + 1:,} / {len(packets):,} packets")

        key = None
        src_endpoint = None

        if pkt.haslayer(TCP):
            key = tcp_stream_key(pkt)
            if key and pkt.haslayer(IP):
                src_endpoint = (pkt[IP].src, pkt[TCP].sport)
            elif key and pkt.haslayer(IPv6):
                src_endpoint = (pkt[IPv6].src, pkt[TCP].sport)
        elif pkt.haslayer(UDP):
            key = udp_stream_key(pkt)
            if key and pkt.haslayer(IP):
                src_endpoint = (pkt[IP].src, pkt[UDP].sport)
            elif key and pkt.haslayer(IPv6):
                src_endpoint = (pkt[IPv6].src, pkt[UDP].sport)

        if key is None or src_endpoint is None:
            continue

        if key not in streams:
            proto, ep_a, ep_b = key
            streams[key] = StreamTracker(proto, ep_a, ep_b)

        streams[key].add_packet(pkt, src_endpoint)

    print(f"  Found {len(streams)} total streams")

    # Apply filters
    filtered = []
    for key, stream in streams.items():
        if matches_filter(stream, host_filter, port_filter):
            filtered.append(stream)

    # Sort by total bytes descending (most active streams first)
    filtered.sort(key=lambda s: s.total_bytes, reverse=True)

    if host_filter or port_filter:
        print(f"  After filtering: {len(filtered)} streams")

    # Cap at max_streams
    if len(filtered) > max_streams:
        print(f"  Capping output to {max_streams} streams (of {len(filtered)})")
        filtered = filtered[:max_streams]

    # Write stream metadata
    meta_path = get_output_path(name, "_streams.json")
    print(f"  Writing stream metadata to {os.path.basename(meta_path)}")

    metadata_list = []
    for idx, stream in enumerate(filtered):
        meta = stream.to_metadata(idx)
        metadata_list.append(meta)

    with open(meta_path, "w") as f:
        json.dump(metadata_list, f, indent=2)

    # Write raw stream data
    output_dir = get_output_dir()
    streams_written = 0
    bytes_written = 0

    for idx, stream in enumerate(filtered):
        raw_data = stream.get_raw_data()
        if not raw_data:
            continue

        bin_path = os.path.join(output_dir, f"{name}_stream_{idx}.bin")
        with open(bin_path, "wb") as f:
            f.write(raw_data)

        streams_written += 1
        bytes_written += len(raw_data)

        if verbose:
            print(f"    Stream {idx}: {stream.proto} "
                  f"{stream.endpoint_a[0]}:{stream.endpoint_a[1]} <-> "
                  f"{stream.endpoint_b[0]}:{stream.endpoint_b[1]} "
                  f"({len(raw_data):,} bytes)")

    print(f"  Wrote {streams_written} stream data files "
          f"({bytes_written:,} bytes total)")

    return len(filtered)


# ---------------------------------------------------------------------------
# Argument parsing and main
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract TCP/UDP streams from a capture file"
    )
    parser.add_argument("capture_file", help="Path to pcap/pcapng file")
    parser.add_argument("--host", default=None,
                        help="Filter to streams involving this IP address")
    parser.add_argument("--port", default=None, type=int,
                        help="Filter to streams involving this port")
    parser.add_argument("--max-streams", default=100, type=int,
                        help="Maximum number of streams to extract (default: 100)")
    return parser.parse_args()


def main():
    args = parse_args()

    capture_file = args.capture_file
    name = os.path.splitext(os.path.basename(capture_file))[0]

    print(f"=== TCP/UDP stream extraction ===")
    print(f"Capture: {capture_file}")
    print(f"Output prefix: {name}")

    if args.host:
        print(f"Host filter: {args.host}")
    if args.port:
        print(f"Port filter: {args.port}")
    print(f"Max streams: {args.max_streams}")

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
        # Write empty metadata
        meta_path = get_output_path(name, "_streams.json")
        with open(meta_path, "w") as f:
            json.dump([], f)
        sys.exit(0)

    try:
        stream_count = extract_streams(
            packets, name,
            host_filter=args.host,
            port_filter=args.port,
            max_streams=args.max_streams,
        )
    except Exception as e:
        print(f"Error during stream extraction: {e}", file=sys.stderr)
        sys.exit(1)

    elapsed = time.time() - start_time
    print(f"\n=== Stream extraction complete ({elapsed:.1f}s) ===")
    print(f"  Extracted {stream_count} streams")


if __name__ == "__main__":
    main()
