#!/usr/bin/env python3
"""Extract HTTP requests and responses from a network capture file.

Parses raw TCP payloads for HTTP methods and response lines, reassembles
multi-packet HTTP transactions, and exports headers, metadata, and bodies.

Output:
  {name}_http.json        - HTTP transaction metadata
  {name}_http_bodies/     - Extracted HTTP request/response bodies
"""

import sys
import os
import json
import re
import hashlib
from collections import defaultdict
from datetime import datetime

from scapy.all import *


# Maximum total bytes to extract for bodies (10 MB)
MAX_BODY_BYTES = 10 * 1024 * 1024

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH")
HTTP_RESPONSE_RE = re.compile(rb"^HTTP/1\.[01]\s+(\d{3})\s+")
HTTP_REQUEST_RE = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)\s+HTTP/1\.[01]\r?\n"
)
HEADER_RE = re.compile(rb"^([A-Za-z0-9\-]+):\s*(.*?)\r?\n")


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
            from scapy.arch import conf as scapy_conf
            filtered = [p for p in packets if p.haslayer(IP)]
            # Apply manual TCP filter since BPF requires libpcap bindings
            if "tcp" in bpf_filter.lower():
                filtered = [p for p in filtered if p.haslayer(TCP)]
            packets = PacketList(filtered)
            print(f"After filtering: {len(packets)} packets (from {total})")
        except Exception as e:
            if verbose:
                print(f"BPF filter note: {e}", file=sys.stderr)

    return packets


def reassemble_tcp_streams(packets, verbose):
    """Group packets by TCP stream (4-tuple) and reassemble payloads."""
    streams = defaultdict(list)

    for pkt in packets:
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]
        # Stream key: sorted endpoints so both directions share a key
        # but we track direction with the packet itself
        src = (ip.src, tcp.sport)
        dst = (ip.dst, tcp.dport)
        stream_key = tuple(sorted([src, dst]))
        streams[stream_key].append(pkt)

    if verbose:
        print(f"Found {len(streams)} TCP streams with payload data")

    return streams


def parse_http_headers(raw_bytes):
    """Parse HTTP headers from raw bytes. Returns (headers_dict, header_end_offset)."""
    headers = {}
    offset = 0
    lines = raw_bytes.split(b"\n")

    # Skip the request/status line
    if lines:
        first_line = lines[0]
        offset = len(first_line) + 1  # +1 for \n

    for line in lines[1:]:
        stripped = line.rstrip(b"\r")
        if stripped == b"":
            offset += len(line) + 1
            break
        match = re.match(rb"^([A-Za-z0-9\-_]+):\s*(.*)", stripped)
        if match:
            key = match.group(1).decode("utf-8", errors="replace").lower()
            val = match.group(2).decode("utf-8", errors="replace")
            headers[key] = val
        offset += len(line) + 1

    return headers, offset


def extract_http_from_stream(stream_packets, verbose):
    """Extract HTTP transactions from a reassembled TCP stream."""
    transactions = []

    # Separate by direction
    if not stream_packets:
        return transactions

    first_pkt = stream_packets[0]
    ip0 = first_pkt[IP]
    tcp0 = first_pkt[TCP]
    client_addr = (ip0.src, tcp0.sport)
    server_addr = (ip0.dst, tcp0.dport)

    # Determine which side is the client by looking for HTTP request
    client_data = bytearray()
    server_data = bytearray()
    client_timestamps = []
    server_timestamps = []

    for pkt in sorted(stream_packets, key=lambda p: float(p.time)):
        ip = pkt[IP]
        tcp = pkt[TCP]
        payload = bytes(pkt[Raw].load)
        src = (ip.src, tcp.sport)

        if src == client_addr:
            client_data.extend(payload)
            client_timestamps.append(float(pkt.time))
        else:
            server_data.extend(payload)
            server_timestamps.append(float(pkt.time))

    # Check if we guessed the direction wrong -- if server_data starts with
    # an HTTP method, swap them
    for method in HTTP_METHODS:
        if server_data.startswith(method):
            client_data, server_data = server_data, client_data
            client_timestamps, server_timestamps = server_timestamps, client_timestamps
            client_addr, server_addr = server_addr, client_addr
            break

    # Parse requests from client data
    requests = []
    remaining = bytes(client_data)
    while remaining:
        match = HTTP_REQUEST_RE.match(remaining)
        if not match:
            break

        method = match.group(1).decode("utf-8", errors="replace")
        uri = match.group(2).decode("utf-8", errors="replace")

        headers, header_end = parse_http_headers(remaining)
        content_length = int(headers.get("content-length", "0"))

        body = b""
        body_end = header_end + content_length
        if content_length > 0 and body_end <= len(remaining):
            body = remaining[header_end:body_end]
        elif content_length > 0:
            body = remaining[header_end:]
            body_end = len(remaining)
        else:
            body_end = header_end

        requests.append({
            "method": method,
            "uri": uri,
            "headers": headers,
            "body": body,
            "body_size": len(body),
        })

        remaining = remaining[body_end:]

    # Parse responses from server data
    responses = []
    remaining = bytes(server_data)
    while remaining:
        match = HTTP_RESPONSE_RE.match(remaining)
        if not match:
            break

        status_code = int(match.group(1))

        headers, header_end = parse_http_headers(remaining)
        content_length = int(headers.get("content-length", "0"))

        # Check for chunked transfer encoding
        is_chunked = "chunked" in headers.get("transfer-encoding", "").lower()

        body = b""
        if is_chunked:
            # Simple chunked decoding: find double CRLF after headers, then
            # read chunks until 0-length chunk
            chunk_data = remaining[header_end:]
            decoded_body = bytearray()
            pos = 0
            while pos < len(chunk_data):
                # Find end of chunk size line
                crlf = chunk_data.find(b"\r\n", pos)
                if crlf == -1:
                    break
                size_str = chunk_data[pos:crlf].split(b";")[0].strip()
                try:
                    chunk_size = int(size_str, 16)
                except ValueError:
                    break
                if chunk_size == 0:
                    pos = crlf + 4  # skip final \r\n\r\n
                    break
                chunk_start = crlf + 2
                chunk_end = chunk_start + chunk_size
                if chunk_end > len(chunk_data):
                    decoded_body.extend(chunk_data[chunk_start:])
                    pos = len(chunk_data)
                    break
                decoded_body.extend(chunk_data[chunk_start:chunk_end])
                pos = chunk_end + 2  # skip trailing \r\n
            body = bytes(decoded_body)
            body_end = header_end + pos
        elif content_length > 0:
            body_end = header_end + content_length
            if body_end <= len(remaining):
                body = remaining[header_end:body_end]
            else:
                body = remaining[header_end:]
                body_end = len(remaining)
        else:
            # No content-length, no chunked -- try to find next HTTP response
            next_http = remaining.find(b"HTTP/1.", header_end + 1)
            if next_http > 0:
                body = remaining[header_end:next_http]
                body_end = next_http
            else:
                body = remaining[header_end:]
                body_end = len(remaining)

        responses.append({
            "status_code": status_code,
            "headers": headers,
            "body": body,
            "body_size": len(body),
        })

        remaining = remaining[body_end:]

    # Pair requests with responses
    for i in range(max(len(requests), len(responses))):
        txn = {
            "index": i,
            "src_ip": client_addr[0],
            "src_port": client_addr[1],
            "dst_ip": server_addr[0],
            "dst_port": server_addr[1],
        }

        if i < len(requests):
            req = requests[i]
            txn["method"] = req["method"]
            txn["uri"] = req["uri"]
            txn["host"] = req["headers"].get("host", server_addr[0])
            txn["url"] = f"http://{txn['host']}{req['uri']}"
            txn["request_headers"] = req["headers"]
            txn["request_content_length"] = req["body_size"]
            txn["request_body_hash"] = hashlib.md5(req["body"]).hexdigest() if req["body"] else None
        else:
            txn["method"] = None
            txn["uri"] = None

        if i < len(responses):
            resp = responses[i]
            txn["status_code"] = resp["status_code"]
            txn["response_headers"] = resp["headers"]
            txn["response_content_type"] = resp["headers"].get("content-type", "")
            txn["response_content_length"] = resp["body_size"]
            txn["response_body_hash"] = hashlib.md5(resp["body"]).hexdigest() if resp["body"] else None
        else:
            txn["status_code"] = None

        if client_timestamps:
            txn["timestamp"] = datetime.utcfromtimestamp(
                client_timestamps[0]
            ).isoformat() + "Z"
        elif server_timestamps:
            txn["timestamp"] = datetime.utcfromtimestamp(
                server_timestamps[0]
            ).isoformat() + "Z"
        else:
            txn["timestamp"] = None

        # Attach raw body bytes for later extraction (not serialized to JSON)
        txn["_request_body"] = requests[i]["body"] if i < len(requests) else b""
        txn["_response_body"] = responses[i]["body"] if i < len(responses) else b""

        transactions.append(txn)

    return transactions


def main():
    capture_file, output_dir, bpf_filter, verbose, name = parse_env()

    json_path = os.path.join(output_dir, f"{name}_http.json")
    bodies_dir = os.path.join(output_dir, f"{name}_http_bodies")

    packets = load_packets(capture_file, bpf_filter, verbose)

    # Filter to TCP packets with payload
    tcp_with_payload = [p for p in packets if p.haslayer(TCP) and p.haslayer(Raw)]
    print(f"TCP packets with payload: {len(tcp_with_payload)}")

    # Quick check: any HTTP-like data?
    http_packet_count = 0
    for pkt in tcp_with_payload:
        payload = bytes(pkt[Raw].load)
        is_request = any(payload.startswith(m) for m in HTTP_METHODS)
        is_response = payload.startswith(b"HTTP/1.")
        if is_request or is_response:
            http_packet_count += 1
    print(f"Packets with HTTP signatures: {http_packet_count}")

    if http_packet_count == 0:
        print("No HTTP traffic found in capture.")
        # Write empty result
        with open(json_path, "w") as f:
            json.dump([], f, indent=2)
        print(f"Wrote empty result to {json_path}")
        return

    # Reassemble TCP streams
    print("Reassembling TCP streams...")
    streams = reassemble_tcp_streams(packets, verbose)

    # Extract HTTP from each stream
    all_transactions = []
    total_body_bytes = 0

    for stream_key, stream_pkts in streams.items():
        try:
            txns = extract_http_from_stream(stream_pkts, verbose)
            all_transactions.extend(txns)
        except Exception as e:
            if verbose:
                print(f"  Error processing stream {stream_key}: {e}", file=sys.stderr)

    print(f"Extracted {len(all_transactions)} HTTP transactions")

    # Re-index transactions globally
    for i, txn in enumerate(all_transactions):
        txn["index"] = i

    # Extract bodies to disk
    if any(txn.get("_request_body") or txn.get("_response_body") for txn in all_transactions):
        os.makedirs(bodies_dir, exist_ok=True)
        print(f"Extracting HTTP bodies to {bodies_dir}/...")

    for txn in all_transactions:
        idx = txn["index"]

        # Request body
        req_body = txn.pop("_request_body", b"")
        if req_body and total_body_bytes < MAX_BODY_BYTES:
            ext = guess_extension(txn.get("request_headers", {}).get("content-type", ""))
            body_path = os.path.join(bodies_dir, f"{idx:04d}_request{ext}")
            try:
                with open(body_path, "wb") as f:
                    f.write(req_body)
                total_body_bytes += len(req_body)
                txn["request_body_file"] = os.path.basename(body_path)
            except Exception as e:
                if verbose:
                    print(f"  Error writing request body {idx}: {e}", file=sys.stderr)
        else:
            txn.pop("_request_body", None)

        # Response body
        resp_body = txn.pop("_response_body", b"")
        if resp_body and total_body_bytes < MAX_BODY_BYTES:
            ext = guess_extension(txn.get("response_content_type", ""))
            body_path = os.path.join(bodies_dir, f"{idx:04d}_response{ext}")
            try:
                with open(body_path, "wb") as f:
                    f.write(resp_body)
                total_body_bytes += len(resp_body)
                txn["response_body_file"] = os.path.basename(body_path)
            except Exception as e:
                if verbose:
                    print(f"  Error writing response body {idx}: {e}", file=sys.stderr)
        else:
            txn.pop("_response_body", None)

        if total_body_bytes >= MAX_BODY_BYTES:
            print(f"Body extraction limit reached ({MAX_BODY_BYTES // (1024*1024)} MB)")
            break

    # Write JSON output
    with open(json_path, "w") as f:
        json.dump(all_transactions, f, indent=2, default=str)

    print(f"Wrote {len(all_transactions)} HTTP transactions to {json_path}")
    if total_body_bytes > 0:
        print(f"Extracted {total_body_bytes:,} bytes of HTTP bodies to {bodies_dir}/")


def guess_extension(content_type):
    """Guess a file extension from a content-type header value."""
    if not content_type:
        return ".bin"
    ct = content_type.lower().split(";")[0].strip()
    ext_map = {
        "text/html": ".html",
        "text/plain": ".txt",
        "text/css": ".css",
        "text/xml": ".xml",
        "text/csv": ".csv",
        "application/json": ".json",
        "application/javascript": ".js",
        "application/xml": ".xml",
        "application/pdf": ".pdf",
        "application/zip": ".zip",
        "application/gzip": ".gz",
        "application/octet-stream": ".bin",
        "application/x-www-form-urlencoded": ".txt",
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/svg+xml": ".svg",
        "image/webp": ".webp",
        "multipart/form-data": ".bin",
    }
    return ext_map.get(ct, ".bin")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
