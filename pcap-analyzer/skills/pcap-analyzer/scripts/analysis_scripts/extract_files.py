#!/usr/bin/env python3
"""Carve transferred files from network streams in packet captures.

Extracts files from HTTP responses, FTP data transfers, SMTP attachments,
and via magic byte detection in raw TCP streams. Computes MD5 hashes for
each extracted file.
"""

import sys
import os
import json
import re
import hashlib
import base64
from collections import defaultdict
from datetime import datetime

from scapy.all import *


# Maximum total extraction size: 50 MB
MAX_TOTAL_BYTES = 50 * 1024 * 1024
# Maximum single file size: 10 MB
MAX_FILE_BYTES = 10 * 1024 * 1024

# Magic byte signatures for file detection in raw streams
MAGIC_SIGNATURES = [
    (b"%PDF", "pdf", "application/pdf"),
    (b"PK\x03\x04", "zip", "application/zip"),
    (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
    (b"\xff\xd8\xff", "jpg", "image/jpeg"),
    (b"MZ", "exe", "application/x-dosexec"),
    (b"\x7fELF", "elf", "application/x-elf"),
    (b"GIF87a", "gif", "image/gif"),
    (b"GIF89a", "gif", "image/gif"),
    (b"\x1f\x8b", "gz", "application/gzip"),
    (b"BZh", "bz2", "application/x-bzip2"),
    (b"Rar!\x1a\x07", "rar", "application/x-rar-compressed"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "doc", "application/msword"),
    (b"{\rtf", "rtf", "application/rtf"),
]

# Content-Type to file extension mapping
CONTENT_TYPE_EXT = {
    "text/html": "html",
    "text/plain": "txt",
    "text/css": "css",
    "text/javascript": "js",
    "application/javascript": "js",
    "application/json": "json",
    "application/xml": "xml",
    "text/xml": "xml",
    "application/pdf": "pdf",
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/gif": "gif",
    "image/svg+xml": "svg",
    "application/zip": "zip",
    "application/gzip": "gz",
    "application/octet-stream": "bin",
    "application/x-executable": "bin",
    "application/x-dosexec": "exe",
    "application/x-elf": "elf",
    "application/msword": "doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/vnd.ms-excel": "xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xlsx",
}


def get_config():
    """Read configuration from environment variables."""
    if len(sys.argv) < 2:
        print("Usage: extract_files.py <capture_file>", file=sys.stderr)
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
    """Load packets from capture file."""
    print(f"Loading {capture_file}...", file=sys.stderr)
    file_size = os.path.getsize(capture_file)
    print(f"  File size: {file_size / (1024*1024):.1f} MB", file=sys.stderr)

    packets = rdpcap(capture_file)
    print(f"  Loaded {len(packets)} packets", file=sys.stderr)

    if bpf_filter:
        try:
            filtered = [p for p in packets if p.haslayer(IP)]
            print(f"  BPF filter set: '{bpf_filter}' (applying IP-layer filter)", file=sys.stderr)
            packets = filtered
        except Exception:
            print(f"  Warning: Could not apply BPF filter, using all packets", file=sys.stderr)

    return packets


def save_extracted_file(data, filename, extract_dir, total_bytes_ref):
    """Save an extracted file to disk, respecting size limits.

    Returns (filepath, md5, size) or None if limits exceeded.
    """
    if len(data) == 0:
        return None

    if len(data) > MAX_FILE_BYTES:
        data = data[:MAX_FILE_BYTES]

    if total_bytes_ref[0] + len(data) > MAX_TOTAL_BYTES:
        remaining = MAX_TOTAL_BYTES - total_bytes_ref[0]
        if remaining <= 0:
            return None
        data = data[:remaining]

    os.makedirs(extract_dir, exist_ok=True)

    # Sanitize filename
    filename = re.sub(r"[^\w\-.]", "_", filename)
    if not filename or filename.startswith("."):
        filename = "extracted_" + filename

    # Handle duplicate filenames
    filepath = os.path.join(extract_dir, filename)
    counter = 1
    base, ext = os.path.splitext(filename)
    while os.path.exists(filepath):
        filepath = os.path.join(extract_dir, f"{base}_{counter}{ext}")
        counter += 1

    md5_hash = hashlib.md5(data).hexdigest()

    with open(filepath, "wb") as f:
        f.write(data)

    total_bytes_ref[0] += len(data)

    return filepath, md5_hash, len(data)


def reassemble_tcp_streams(packets):
    """Reassemble TCP streams from packets, grouped by connection tuple.

    Returns dict of (src_ip, dst_ip, src_port, dst_port) -> list of (timestamp, data) in seq order.
    """
    streams = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            seq = pkt[TCP].seq
            ts = float(pkt.time)
            data = bytes(pkt[Raw].load)

            key = (src_ip, dst_ip, sport, dport)
            streams[key].append((seq, ts, data))

    # Sort each stream by sequence number
    for key in streams:
        streams[key].sort(key=lambda x: x[0])

    return streams


def extract_http_files(packets, extract_dir, total_bytes_ref, verbose=False):
    """Extract files from HTTP responses with Content-Type and bodies.

    Handles both regular and chunked transfer encoding.
    """
    print("  Extracting files from HTTP responses...", file=sys.stderr)
    findings = []

    # Reassemble TCP streams to get full HTTP responses
    streams = reassemble_tcp_streams(packets)

    file_counter = 0

    for (src_ip, dst_ip, sport, dport), segments in streams.items():
        # HTTP responses typically come from server (sport=80)
        if sport not in (80, 8080, 8000, 8888, 3000, 5000):
            continue

        # Concatenate stream data
        stream_data = b""
        first_ts = None
        for seq, ts, data in segments:
            if first_ts is None:
                first_ts = ts
            stream_data += data
            # Safety limit per stream
            if len(stream_data) > MAX_FILE_BYTES * 2:
                break

        if not stream_data:
            continue

        # Split on HTTP response boundaries
        # Look for "HTTP/1.x NNN" patterns
        responses = re.split(b"(HTTP/1\\.[01]\\s+\\d{3}[^\r\n]*\r?\n)", stream_data)

        i = 0
        while i < len(responses) - 1:
            # Find response start
            if not re.match(b"HTTP/1\\.[01]\\s+\\d{3}", responses[i]):
                i += 1
                continue

            response_header_start = responses[i]
            response_rest = responses[i + 1] if i + 1 < len(responses) else b""
            full_response = response_header_start + response_rest
            i += 2

            # Split headers from body
            header_body_split = full_response.split(b"\r\n\r\n", 1)
            if len(header_body_split) < 2:
                header_body_split = full_response.split(b"\n\n", 1)
            if len(header_body_split) < 2:
                continue

            headers_raw = header_body_split[0]
            body = header_body_split[1]

            try:
                headers_text = headers_raw.decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Parse Content-Type
            ct_match = re.search(r"[Cc]ontent-[Tt]ype:\s*([^\r\n;]+)", headers_text)
            if not ct_match:
                continue

            content_type = ct_match.group(1).strip().lower()

            # Skip tiny text responses (HTML pages, etc. under 100 bytes)
            if content_type.startswith("text/html") and len(body) < 100:
                continue

            # Parse Content-Length
            cl_match = re.search(r"[Cc]ontent-[Ll]ength:\s*(\d+)", headers_text)
            content_length = int(cl_match.group(1)) if cl_match else None

            # Parse Content-Disposition for filename
            cd_match = re.search(r'[Cc]ontent-[Dd]isposition:.*?filename[*]?=(?:"([^"]+)"|(\S+))', headers_text)
            filename = None
            if cd_match:
                filename = cd_match.group(1) or cd_match.group(2)
                filename = filename.strip("\"' ")

            # Check for chunked transfer encoding
            is_chunked = "transfer-encoding: chunked" in headers_text.lower()

            if is_chunked:
                # Reassemble chunked encoding
                decoded_body = b""
                pos = 0
                try:
                    while pos < len(body):
                        # Find end of chunk size line
                        eol = body.find(b"\r\n", pos)
                        if eol == -1:
                            break
                        chunk_size_str = body[pos:eol].decode("ascii", errors="ignore").strip()
                        if not chunk_size_str:
                            pos = eol + 2
                            continue
                        # Remove chunk extensions
                        chunk_size_str = chunk_size_str.split(";")[0].strip()
                        chunk_size = int(chunk_size_str, 16)
                        if chunk_size == 0:
                            break
                        chunk_start = eol + 2
                        chunk_end = chunk_start + chunk_size
                        if chunk_end > len(body):
                            decoded_body += body[chunk_start:]
                            break
                        decoded_body += body[chunk_start:chunk_end]
                        pos = chunk_end + 2  # Skip trailing \r\n
                        if len(decoded_body) > MAX_FILE_BYTES:
                            break
                except Exception:
                    decoded_body = body  # Fallback to raw body
                body = decoded_body
            elif content_length and content_length < len(body):
                body = body[:content_length]

            if len(body) < 10:
                continue

            if total_bytes_ref[0] >= MAX_TOTAL_BYTES:
                print("  Reached total extraction limit (50 MB)", file=sys.stderr)
                return findings

            # Generate filename if not from Content-Disposition
            if not filename:
                ext = CONTENT_TYPE_EXT.get(content_type, "bin")
                file_counter += 1
                filename = f"http_{file_counter:04d}.{ext}"

            result = save_extracted_file(body, filename, extract_dir, total_bytes_ref)
            if result:
                filepath, md5_hash, size = result
                findings.append({
                    "filename": os.path.basename(filepath),
                    "content_type": content_type,
                    "size": size,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "HTTP",
                    "timestamp": first_ts,
                    "md5": md5_hash,
                    "extraction_path": filepath,
                })

                if verbose:
                    print(f"    HTTP file: {os.path.basename(filepath)} ({content_type}, {size} bytes)", file=sys.stderr)

    return findings


def extract_ftp_files(packets, extract_dir, total_bytes_ref, verbose=False):
    """Extract files from FTP data transfers.

    Tracks PORT/PASV commands on control channel (port 21) and correlates
    with data connections.
    """
    print("  Extracting files from FTP transfers...", file=sys.stderr)
    findings = []

    # Track FTP control channel for filenames and data port info
    ftp_state = defaultdict(lambda: {
        "filename": None,
        "data_port": None,
        "type": None,
        "ts": None,
    })

    # First pass: parse FTP control channel
    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport != 21 and sport != 21:
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ts = float(pkt.time)

        # RETR command (download)
        retr_match = re.match(r"RETR\s+(.+)", payload, re.IGNORECASE)
        if retr_match:
            session_key = (src_ip, dst_ip)
            ftp_state[session_key]["filename"] = retr_match.group(1).strip()
            ftp_state[session_key]["type"] = "download"
            ftp_state[session_key]["ts"] = ts

        # STOR command (upload)
        stor_match = re.match(r"STOR\s+(.+)", payload, re.IGNORECASE)
        if stor_match:
            session_key = (src_ip, dst_ip)
            ftp_state[session_key]["filename"] = stor_match.group(1).strip()
            ftp_state[session_key]["type"] = "upload"
            ftp_state[session_key]["ts"] = ts

        # PASV response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
        pasv_match = re.search(r"227\s+.*\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", payload)
        if pasv_match:
            p1, p2 = int(pasv_match.group(5)), int(pasv_match.group(6))
            data_port = p1 * 256 + p2
            # Server is the source of this response
            session_key = (dst_ip, src_ip)  # Client -> Server perspective
            ftp_state[session_key]["data_port"] = data_port

        # PORT command: PORT h1,h2,h3,h4,p1,p2
        port_match = re.match(r"PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", payload, re.IGNORECASE)
        if port_match:
            p1, p2 = int(port_match.group(5)), int(port_match.group(6))
            data_port = p1 * 256 + p2
            session_key = (src_ip, dst_ip)
            ftp_state[session_key]["data_port"] = data_port

    # Second pass: extract data from FTP data connections
    # Common FTP data ports: 20, and dynamic ports from PASV
    data_ports = {20}
    for session in ftp_state.values():
        if session["data_port"]:
            data_ports.add(session["data_port"])

    streams = reassemble_tcp_streams(packets)
    file_counter = 0

    for (src_ip, dst_ip, sport, dport), segments in streams.items():
        if sport not in data_ports and dport not in data_ports:
            continue

        # Concatenate stream data
        stream_data = b""
        first_ts = None
        for seq, ts, data in segments:
            if first_ts is None:
                first_ts = ts
            stream_data += data
            if len(stream_data) > MAX_FILE_BYTES:
                break

        if len(stream_data) < 10:
            continue

        if total_bytes_ref[0] >= MAX_TOTAL_BYTES:
            print("  Reached total extraction limit (50 MB)", file=sys.stderr)
            return findings

        # Try to find associated filename from FTP state
        filename = None
        for session_key, state in ftp_state.items():
            if state["filename"]:
                # Match by IP pair (either direction for data channel)
                if (src_ip in session_key and dst_ip in session_key):
                    filename = os.path.basename(state["filename"])
                    break

        if not filename:
            # Detect by magic bytes
            ext = detect_magic_extension(stream_data)
            file_counter += 1
            filename = f"ftp_{file_counter:04d}.{ext}"

        result = save_extracted_file(stream_data, filename, extract_dir, total_bytes_ref)
        if result:
            filepath, md5_hash, size = result
            findings.append({
                "filename": os.path.basename(filepath),
                "content_type": detect_content_type(stream_data),
                "size": size,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "FTP",
                "timestamp": first_ts,
                "md5": md5_hash,
                "extraction_path": filepath,
            })

            if verbose:
                print(f"    FTP file: {os.path.basename(filepath)} ({size} bytes)", file=sys.stderr)

    return findings


def extract_smtp_attachments(packets, extract_dir, total_bytes_ref, verbose=False):
    """Extract SMTP attachments from MIME-encoded email messages.

    Looks for MIME boundaries and Base64-encoded content parts.
    """
    print("  Extracting SMTP attachments...", file=sys.stderr)
    findings = []

    streams = reassemble_tcp_streams(packets)
    file_counter = 0

    for (src_ip, dst_ip, sport, dport), segments in streams.items():
        if dport not in (25, 587, 2525) and sport not in (25, 587, 2525):
            continue

        # Concatenate stream
        stream_data = b""
        first_ts = None
        for seq, ts, data in segments:
            if first_ts is None:
                first_ts = ts
            stream_data += data
            if len(stream_data) > MAX_FILE_BYTES * 2:
                break

        if len(stream_data) < 100:
            continue

        try:
            text = stream_data.decode("utf-8", errors="ignore")
        except Exception:
            continue

        # Find MIME boundary
        boundary_match = re.search(r'boundary="?([^"\r\n;]+)"?', text, re.IGNORECASE)
        if not boundary_match:
            continue

        boundary = boundary_match.group(1).strip()

        # Split by boundary
        parts = text.split("--" + boundary)

        for part in parts:
            if not part.strip() or part.strip() == "--":
                continue

            # Check for Content-Disposition: attachment
            if "content-disposition" not in part.lower():
                continue

            # Extract filename
            fname_match = re.search(r'filename[*]?=(?:"([^"]+)"|(\S+))', part, re.IGNORECASE)
            filename = None
            if fname_match:
                filename = fname_match.group(1) or fname_match.group(2)
                filename = filename.strip("\"' ")

            # Extract Content-Type
            ct_match = re.search(r"[Cc]ontent-[Tt]ype:\s*([^\r\n;]+)", part)
            content_type = ct_match.group(1).strip() if ct_match else "application/octet-stream"

            # Check for Content-Transfer-Encoding: base64
            is_base64 = "content-transfer-encoding: base64" in part.lower()

            # Extract body (after the blank line in the MIME part)
            body_parts = re.split(r"\r?\n\r?\n", part, maxsplit=1)
            if len(body_parts) < 2:
                continue

            body_text = body_parts[1].strip()

            if is_base64:
                # Remove whitespace and decode
                clean = re.sub(r"\s+", "", body_text)
                try:
                    decoded = base64.b64decode(clean)
                except Exception:
                    continue
            else:
                decoded = body_text.encode("utf-8", errors="ignore")

            if len(decoded) < 10:
                continue

            if total_bytes_ref[0] >= MAX_TOTAL_BYTES:
                print("  Reached total extraction limit (50 MB)", file=sys.stderr)
                return findings

            if not filename:
                ext = CONTENT_TYPE_EXT.get(content_type.lower(), detect_magic_extension(decoded))
                file_counter += 1
                filename = f"smtp_{file_counter:04d}.{ext}"

            result = save_extracted_file(decoded, filename, extract_dir, total_bytes_ref)
            if result:
                filepath, md5_hash, size = result
                findings.append({
                    "filename": os.path.basename(filepath),
                    "content_type": content_type,
                    "size": size,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": "SMTP",
                    "timestamp": first_ts,
                    "md5": md5_hash,
                    "extraction_path": filepath,
                })

                if verbose:
                    print(f"    SMTP attachment: {os.path.basename(filepath)} ({content_type}, {size} bytes)", file=sys.stderr)

    return findings


def detect_magic_extension(data):
    """Detect file type from magic bytes."""
    for magic, ext, _ in MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            return ext
    return "bin"


def detect_content_type(data):
    """Detect content type from magic bytes."""
    for magic, _, ctype in MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            return ctype
    return "application/octet-stream"


def extract_magic_files(packets, extract_dir, total_bytes_ref, verbose=False):
    """Detect and extract files by magic byte signatures in TCP streams.

    Scans reassembled TCP stream data for known file signatures (PDF, ZIP,
    PNG, JPEG, PE, ELF, etc.) and carves them out.
    """
    print("  Extracting files by magic byte detection...", file=sys.stderr)
    findings = []

    streams = reassemble_tcp_streams(packets)
    file_counter = 0

    # Track already-extracted MD5s to avoid duplicates
    seen_md5 = set()

    for (src_ip, dst_ip, sport, dport), segments in streams.items():
        # Skip well-known protocol ports already handled
        if sport in (80, 8080, 8000, 8888, 21, 20, 25, 587) or \
           dport in (80, 8080, 8000, 8888, 21, 20, 25, 587):
            continue

        # Concatenate stream
        stream_data = b""
        first_ts = None
        for seq, ts, data in segments:
            if first_ts is None:
                first_ts = ts
            stream_data += data
            if len(stream_data) > MAX_FILE_BYTES * 2:
                break

        if len(stream_data) < 20:
            continue

        # Scan for magic bytes
        for magic, ext, content_type in MAGIC_SIGNATURES:
            offset = 0
            while offset < len(stream_data) - len(magic):
                pos = stream_data.find(magic, offset)
                if pos == -1:
                    break

                if total_bytes_ref[0] >= MAX_TOTAL_BYTES:
                    print("  Reached total extraction limit (50 MB)", file=sys.stderr)
                    return findings

                # Determine file end heuristically
                file_data = _carve_file(stream_data, pos, ext)

                if len(file_data) < 20:
                    offset = pos + len(magic)
                    continue

                # Check for duplicate
                md5_hash = hashlib.md5(file_data).hexdigest()
                if md5_hash in seen_md5:
                    offset = pos + len(magic)
                    continue
                seen_md5.add(md5_hash)

                file_counter += 1
                filename = f"carved_{file_counter:04d}.{ext}"

                result = save_extracted_file(file_data, filename, extract_dir, total_bytes_ref)
                if result:
                    filepath, md5_hash, size = result
                    findings.append({
                        "filename": os.path.basename(filepath),
                        "content_type": content_type,
                        "size": size,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "protocol": f"TCP/{dport}",
                        "timestamp": first_ts,
                        "md5": md5_hash,
                        "extraction_path": filepath,
                        "carved": True,
                        "stream_offset": pos,
                    })

                    if verbose:
                        print(f"    Carved: {os.path.basename(filepath)} ({content_type}, {size} bytes) at offset {pos}", file=sys.stderr)

                offset = pos + len(file_data)

    return findings


def _carve_file(data, start, ext):
    """Heuristically carve a file from stream data starting at offset.

    Uses file-format-specific end markers where possible, with a fallback
    to MAX_FILE_BYTES.
    """
    remaining = data[start:]
    max_len = min(len(remaining), MAX_FILE_BYTES)

    if ext == "pdf":
        # PDF ends with %%EOF
        eof_marker = remaining.find(b"%%EOF")
        if eof_marker != -1:
            return remaining[:eof_marker + 5]
        return remaining[:max_len]

    elif ext == "zip":
        # ZIP end of central directory: PK\x05\x06
        eocd = remaining.find(b"PK\x05\x06")
        if eocd != -1:
            # EOCD record is at least 22 bytes
            return remaining[:eocd + 22]
        return remaining[:max_len]

    elif ext == "png":
        # PNG ends with IEND chunk
        iend = remaining.find(b"IEND")
        if iend != -1:
            # IEND chunk: 4 len + 4 type + 4 CRC = after the IEND marker + 8
            return remaining[:iend + 8]
        return remaining[:max_len]

    elif ext == "jpg":
        # JPEG ends with FFD9
        eoi = remaining.find(b"\xff\xd9")
        if eoi != -1:
            return remaining[:eoi + 2]
        return remaining[:max_len]

    elif ext == "gif":
        # GIF ends with 0x3B
        trailer = remaining.find(b"\x3b", 10)  # Skip header
        if trailer != -1:
            return remaining[:trailer + 1]
        return remaining[:max_len]

    elif ext in ("exe", "elf"):
        # For executables, take a reasonable chunk
        # PE: look for the size from headers if possible
        return remaining[:max_len]

    else:
        # Default: take up to max size
        return remaining[:max_len]


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

    print(f"Analyzing {len(packets)} packets for file extraction...", file=sys.stderr)

    extract_dir = os.path.join(config["output_dir"], f"{config['name']}_extracted")
    os.makedirs(extract_dir, exist_ok=True)

    # Mutable reference for tracking total bytes across all extractors
    total_bytes_ref = [0]

    all_files = []

    # HTTP file extraction
    try:
        http_files = extract_http_files(packets, extract_dir, total_bytes_ref, config["verbose"])
        all_files.extend(http_files)
        print(f"    Found {len(http_files)} HTTP files", file=sys.stderr)
    except Exception as e:
        print(f"  Warning: HTTP file extraction failed: {e}", file=sys.stderr)

    # FTP file extraction
    try:
        ftp_files = extract_ftp_files(packets, extract_dir, total_bytes_ref, config["verbose"])
        all_files.extend(ftp_files)
        print(f"    Found {len(ftp_files)} FTP files", file=sys.stderr)
    except Exception as e:
        print(f"  Warning: FTP file extraction failed: {e}", file=sys.stderr)

    # SMTP attachment extraction
    try:
        smtp_files = extract_smtp_attachments(packets, extract_dir, total_bytes_ref, config["verbose"])
        all_files.extend(smtp_files)
        print(f"    Found {len(smtp_files)} SMTP attachments", file=sys.stderr)
    except Exception as e:
        print(f"  Warning: SMTP attachment extraction failed: {e}", file=sys.stderr)

    # Magic byte carving from other TCP streams
    try:
        carved_files = extract_magic_files(packets, extract_dir, total_bytes_ref, config["verbose"])
        all_files.extend(carved_files)
        print(f"    Found {len(carved_files)} carved files", file=sys.stderr)
    except Exception as e:
        print(f"  Warning: Magic byte file carving failed: {e}", file=sys.stderr)

    # Build metadata output
    result = {
        "capture_file": os.path.basename(config["capture_file"]),
        "total_packets": len(packets),
        "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
        "extraction_directory": extract_dir,
        "total_bytes_extracted": total_bytes_ref[0],
        "max_total_bytes": MAX_TOTAL_BYTES,
        "max_file_bytes": MAX_FILE_BYTES,
        "files": all_files,
        "summary": {
            "total_files": len(all_files),
            "total_bytes": total_bytes_ref[0],
            "by_protocol": {},
            "by_content_type": {},
        },
    }

    # Compute summary stats
    proto_counts = defaultdict(int)
    type_counts = defaultdict(int)
    for f in all_files:
        proto_counts[f["protocol"]] += 1
        type_counts[f.get("content_type", "unknown")] += 1
    result["summary"]["by_protocol"] = dict(proto_counts)
    result["summary"]["by_content_type"] = dict(type_counts)

    # Write metadata JSON
    output_path = os.path.join(config["output_dir"], f"{config['name']}_files.json")
    os.makedirs(config["output_dir"], exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\nResults:", file=sys.stderr)
    print(f"  Total files extracted:  {len(all_files)}", file=sys.stderr)
    print(f"  Total bytes extracted:  {total_bytes_ref[0]} ({total_bytes_ref[0]/(1024*1024):.2f} MB)", file=sys.stderr)
    if proto_counts:
        print(f"  By protocol:", file=sys.stderr)
        for proto, count in sorted(proto_counts.items()):
            print(f"    {proto}: {count}", file=sys.stderr)
    if type_counts:
        print(f"  By content type:", file=sys.stderr)
        for ct, count in sorted(type_counts.items()):
            print(f"    {ct}: {count}", file=sys.stderr)
    print(f"  Extraction directory:   {extract_dir}", file=sys.stderr)
    print(f"Output: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
