#!/usr/bin/env python3
"""Extract cleartext credentials and authentication data from packet captures.

Searches for HTTP Basic/Digest auth, form POST data, FTP credentials,
SMTP AUTH, Telnet logins, session cookies, and API key patterns.
"""

import sys
import os
import json
import re
import base64
from collections import defaultdict
from datetime import datetime

from scapy.all import *


def get_config():
    """Read configuration from environment variables."""
    if len(sys.argv) < 2:
        print("Usage: extract_credentials.py <capture_file>", file=sys.stderr)
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


def redact_password(value):
    """Redact a password/secret value, showing only first and last characters.

    Examples: 'mysecretpassword' -> 'm**************d'
              'ab' -> 'a*b'
              'a' -> 'a'
    """
    if not value or len(value) <= 2:
        return value
    return value[0] + "*" * (len(value) - 2) + value[-1]


def get_packet_info(pkt):
    """Extract common packet metadata."""
    info = {
        "timestamp": float(pkt.time),
        "src_ip": pkt[IP].src if pkt.haslayer(IP) else "unknown",
        "dst_ip": pkt[IP].dst if pkt.haslayer(IP) else "unknown",
    }
    if pkt.haslayer(TCP):
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport
    return info


def extract_http_auth(packets, verbose=False):
    """Extract HTTP Basic and Digest authentication headers.

    Decodes Base64 for Basic auth to extract username:password.
    """
    print("  Extracting HTTP authentication headers...", file=sys.stderr)
    findings = []

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport not in (80, 8080, 8000, 8888, 3000, 5000) and sport not in (80, 8080, 8000, 8888, 3000, 5000):
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            continue

        info = get_packet_info(pkt)

        # HTTP Basic Auth
        basic_match = re.search(r"[Aa]uthorization:\s*[Bb]asic\s+([A-Za-z0-9+/=]+)", payload)
        if basic_match:
            b64_value = basic_match.group(1)
            try:
                decoded = base64.b64decode(b64_value).decode("utf-8", errors="replace")
                parts = decoded.split(":", 1)
                username = parts[0] if parts else ""
                password = parts[1] if len(parts) > 1 else ""

                findings.append({
                    **info,
                    "protocol": "HTTP",
                    "credential_type": "basic_auth",
                    "username": username,
                    "password_redacted": redact_password(password),
                    "raw_context": f"Authorization: Basic {b64_value[:20]}...",
                })

                if verbose:
                    print(f"    HTTP Basic: {username}@{info['dst_ip']}", file=sys.stderr)
            except Exception:
                findings.append({
                    **info,
                    "protocol": "HTTP",
                    "credential_type": "basic_auth",
                    "value": f"Basic {b64_value[:30]}...",
                    "raw_context": basic_match.group(0)[:100],
                })

        # HTTP Digest Auth
        digest_match = re.search(r"[Aa]uthorization:\s*[Dd]igest\s+(.+?)(?:\r?\n|$)", payload)
        if digest_match:
            digest_str = digest_match.group(1)
            username_match = re.search(r'username="([^"]*)"', digest_str)
            realm_match = re.search(r'realm="([^"]*)"', digest_str)
            nonce_match = re.search(r'nonce="([^"]*)"', digest_str)
            uri_match = re.search(r'uri="([^"]*)"', digest_str)

            findings.append({
                **info,
                "protocol": "HTTP",
                "credential_type": "digest_auth",
                "username": username_match.group(1) if username_match else "",
                "realm": realm_match.group(1) if realm_match else "",
                "nonce": nonce_match.group(1)[:20] + "..." if nonce_match else "",
                "uri": uri_match.group(1) if uri_match else "",
                "raw_context": digest_str[:200],
            })

            if verbose:
                user = username_match.group(1) if username_match else "?"
                print(f"    HTTP Digest: {user}@{info['dst_ip']}", file=sys.stderr)

        # Proxy-Authorization
        proxy_match = re.search(r"[Pp]roxy-[Aa]uthorization:\s*(Basic|Digest)\s+(.+?)(?:\r?\n|$)", payload)
        if proxy_match:
            auth_type = proxy_match.group(1)
            auth_value = proxy_match.group(2)

            entry = {
                **info,
                "protocol": "HTTP",
                "credential_type": f"proxy_{auth_type.lower()}_auth",
                "raw_context": f"Proxy-Authorization: {auth_type} {auth_value[:40]}...",
            }

            if auth_type.lower() == "basic":
                try:
                    decoded = base64.b64decode(auth_value).decode("utf-8", errors="replace")
                    parts = decoded.split(":", 1)
                    entry["username"] = parts[0] if parts else ""
                    entry["password_redacted"] = redact_password(parts[1]) if len(parts) > 1 else ""
                except Exception:
                    entry["value"] = auth_value[:40]

            findings.append(entry)

    return findings


def extract_http_forms(packets, verbose=False):
    """Extract POST data containing password/login/auth fields."""
    print("  Extracting HTTP form credentials...", file=sys.stderr)
    findings = []

    # Patterns that suggest credential fields
    cred_patterns = re.compile(
        r"(?:^|&)"
        r"((?:user(?:name)?|login|email|passwd|password|pass|pwd|"
        r"auth|token|secret|credential|pin|ssn|account)"
        r"[_\-]?(?:name|word|wd)?)"
        r"=([^&\r\n]+)",
        re.IGNORECASE,
    )

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        dport = pkt[TCP].dport
        if dport not in (80, 8080, 8000, 8888, 3000, 5000):
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            continue

        # Check for POST request with form data
        if not payload.startswith("POST "):
            continue

        info = get_packet_info(pkt)

        # Extract the URL from POST line
        post_match = re.match(r"POST\s+(\S+)", payload)
        url = post_match.group(1) if post_match else ""

        # Look for Content-Type: application/x-www-form-urlencoded
        # Body is after \r\n\r\n
        parts = payload.split("\r\n\r\n", 1)
        if len(parts) < 2:
            continue

        body = parts[1]
        matches = cred_patterns.findall(body)

        if matches:
            form_data = {}
            for field_name, field_value in matches:
                # Redact password-like fields
                if any(p in field_name.lower() for p in ["pass", "pwd", "secret", "pin", "ssn"]):
                    from urllib.parse import unquote
                    try:
                        decoded_value = unquote(field_value)
                    except Exception:
                        decoded_value = field_value
                    form_data[field_name] = redact_password(decoded_value)
                else:
                    from urllib.parse import unquote
                    try:
                        form_data[field_name] = unquote(field_value)[:100]
                    except Exception:
                        form_data[field_name] = field_value[:100]

            findings.append({
                **info,
                "protocol": "HTTP",
                "credential_type": "form_post",
                "url": url[:200],
                "fields": form_data,
                "raw_context": body[:300],
            })

            if verbose:
                print(f"    HTTP Form: POST {url[:60]} fields={list(form_data.keys())}", file=sys.stderr)

    return findings


def extract_ftp_credentials(packets, verbose=False):
    """Extract FTP USER and PASS commands."""
    print("  Extracting FTP credentials...", file=sys.stderr)
    findings = []

    # Track FTP sessions to pair USER/PASS
    ftp_sessions = defaultdict(lambda: {"user": None, "pass": None, "timestamp": None})

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

        info = get_packet_info(pkt)
        session_key = (info["src_ip"], info["dst_ip"])

        # FTP USER command
        user_match = re.match(r"USER\s+(.+)", payload, re.IGNORECASE)
        if user_match:
            ftp_sessions[session_key]["user"] = user_match.group(1).strip()
            ftp_sessions[session_key]["timestamp"] = info["timestamp"]

        # FTP PASS command
        pass_match = re.match(r"PASS\s+(.+)", payload, re.IGNORECASE)
        if pass_match:
            ftp_sessions[session_key]["pass"] = pass_match.group(1).strip()
            if not ftp_sessions[session_key]["timestamp"]:
                ftp_sessions[session_key]["timestamp"] = info["timestamp"]

    # Emit paired credentials
    for (src_ip, dst_ip), session in ftp_sessions.items():
        if session["user"] or session["pass"]:
            entry = {
                "timestamp": session["timestamp"],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "FTP",
                "credential_type": "ftp_login",
                "username": session["user"] or "",
                "password_redacted": redact_password(session["pass"] or ""),
                "raw_context": f"USER {session['user'] or '?'} / PASS {'*' * 6}",
            }
            findings.append(entry)

            if verbose:
                print(f"    FTP: {session['user']}@{dst_ip}", file=sys.stderr)

    return findings


def extract_smtp_auth(packets, verbose=False):
    """Extract SMTP AUTH commands (AUTH LOGIN, AUTH PLAIN)."""
    print("  Extracting SMTP authentication...", file=sys.stderr)
    findings = []

    # Track SMTP AUTH sequences per connection
    smtp_sessions = defaultdict(lambda: {"state": None, "username_b64": None, "password_b64": None, "ts": None})

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport not in (25, 587, 2525) and sport not in (25, 587, 2525):
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
        except Exception:
            continue

        info = get_packet_info(pkt)
        session_key = (info["src_ip"], info["dst_ip"])

        # AUTH PLAIN <base64>
        plain_match = re.match(r"AUTH\s+PLAIN\s+(.+)", payload, re.IGNORECASE)
        if plain_match:
            try:
                decoded = base64.b64decode(plain_match.group(1)).decode("utf-8", errors="replace")
                # AUTH PLAIN format: \0username\0password
                parts = decoded.split("\0")
                username = parts[1] if len(parts) > 1 else ""
                password = parts[2] if len(parts) > 2 else ""
                findings.append({
                    **info,
                    "protocol": "SMTP",
                    "credential_type": "smtp_auth_plain",
                    "username": username,
                    "password_redacted": redact_password(password),
                    "raw_context": f"AUTH PLAIN {plain_match.group(1)[:30]}...",
                })
                if verbose:
                    print(f"    SMTP PLAIN: {username}@{info['dst_ip']}", file=sys.stderr)
            except Exception:
                findings.append({
                    **info,
                    "protocol": "SMTP",
                    "credential_type": "smtp_auth_plain",
                    "value": plain_match.group(1)[:40],
                    "raw_context": payload[:100],
                })
            continue

        # AUTH LOGIN (multi-step: server sends challenges, client sends base64)
        if re.match(r"AUTH\s+LOGIN", payload, re.IGNORECASE):
            smtp_sessions[session_key]["state"] = "waiting_username"
            smtp_sessions[session_key]["ts"] = info["timestamp"]
            continue

        session = smtp_sessions.get(session_key)
        if session and session["state"] == "waiting_username":
            # This should be the base64-encoded username
            if re.match(r"^[A-Za-z0-9+/=]+$", payload) and len(payload) < 200:
                try:
                    session["username_b64"] = base64.b64decode(payload).decode("utf-8", errors="replace")
                except Exception:
                    session["username_b64"] = payload
                session["state"] = "waiting_password"
                continue

        if session and session["state"] == "waiting_password":
            # This should be the base64-encoded password
            if re.match(r"^[A-Za-z0-9+/=]+$", payload) and len(payload) < 200:
                try:
                    password = base64.b64decode(payload).decode("utf-8", errors="replace")
                except Exception:
                    password = payload
                findings.append({
                    "timestamp": session["ts"],
                    "src_ip": session_key[0],
                    "dst_ip": session_key[1],
                    "protocol": "SMTP",
                    "credential_type": "smtp_auth_login",
                    "username": session["username_b64"] or "",
                    "password_redacted": redact_password(password),
                    "raw_context": f"AUTH LOGIN -> {session['username_b64']}:{'*' * 6}",
                })
                if verbose:
                    print(f"    SMTP LOGIN: {session['username_b64']}@{session_key[1]}", file=sys.stderr)

            smtp_sessions[session_key] = {"state": None, "username_b64": None, "password_b64": None, "ts": None}

    return findings


def extract_telnet_credentials(packets, verbose=False):
    """Extract Telnet login sequences.

    Tracks character-by-character telnet input following login/password prompts.
    """
    print("  Extracting Telnet credentials...", file=sys.stderr)
    findings = []

    # Accumulate telnet data per session
    telnet_sessions = defaultdict(lambda: {"data": b"", "ts": None})

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport != 23 and sport != 23:
            continue

        try:
            payload = pkt[Raw].load
        except Exception:
            continue

        info = get_packet_info(pkt)
        # Use both directions for the session key
        if dport == 23:
            session_key = (info["src_ip"], info["dst_ip"])
        else:
            session_key = (info["dst_ip"], info["src_ip"])

        if not telnet_sessions[session_key]["ts"]:
            telnet_sessions[session_key]["ts"] = info["timestamp"]
        telnet_sessions[session_key]["data"] += payload

    # Parse accumulated telnet data for login sequences
    for (client_ip, server_ip), session in telnet_sessions.items():
        data = session["data"]
        try:
            text = data.decode("utf-8", errors="ignore")
        except Exception:
            continue

        text_lower = text.lower()

        # Look for login/username prompts followed by input
        login_patterns = [
            (r"(?:login|username)[:\s]+(\S+)", "username"),
            (r"(?:password)[:\s]+(\S+)", "password"),
        ]

        username = None
        password = None

        for pattern, field_type in login_patterns:
            match = re.search(pattern, text_lower)
            if match:
                value = match.group(1)
                # Clean telnet control characters
                value = re.sub(r"[\x00-\x1f\x7f-\xff]", "", value)
                if field_type == "username":
                    username = value
                elif field_type == "password":
                    password = value

        if username or password:
            findings.append({
                "timestamp": session["ts"],
                "src_ip": client_ip,
                "dst_ip": server_ip,
                "protocol": "Telnet",
                "credential_type": "telnet_login",
                "username": username or "",
                "password_redacted": redact_password(password or ""),
                "raw_context": f"Telnet session to {server_ip}:23",
            })

            if verbose:
                print(f"    Telnet: {username}@{server_ip}", file=sys.stderr)

    return findings


def extract_cookies(packets, verbose=False):
    """Extract session cookies from HTTP traffic."""
    print("  Extracting HTTP cookies...", file=sys.stderr)
    findings = []
    seen_cookies = set()

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        if dport not in (80, 8080, 8000, 8888, 3000, 5000) and sport not in (80, 8080, 8000, 8888, 3000, 5000):
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            continue

        info = get_packet_info(pkt)

        # Client-sent cookies
        cookie_match = re.search(r"[Cc]ookie:\s*(.+?)(?:\r?\n|$)", payload)
        if cookie_match:
            cookie_str = cookie_match.group(1).strip()
            # Parse individual cookies
            cookies = {}
            for part in cookie_str.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()

            # Look for session-like cookies
            session_keywords = ["session", "sess", "sid", "token", "auth", "jwt", "csrftoken", "phpsessid"]
            interesting = {k: v for k, v in cookies.items() if any(kw in k.lower() for kw in session_keywords)}

            if interesting:
                cookie_key = (info["src_ip"], info["dst_ip"], frozenset(interesting.keys()))
                if cookie_key not in seen_cookies:
                    seen_cookies.add(cookie_key)
                    # Redact cookie values
                    redacted = {k: redact_password(v) for k, v in interesting.items()}
                    findings.append({
                        **info,
                        "protocol": "HTTP",
                        "credential_type": "session_cookie",
                        "cookies": redacted,
                        "cookie_count": len(cookies),
                        "raw_context": f"Cookie: {cookie_str[:200]}",
                    })

        # Server Set-Cookie headers
        set_cookie_matches = re.findall(r"[Ss]et-[Cc]ookie:\s*(.+?)(?:\r?\n|$)", payload)
        for sc in set_cookie_matches:
            sc = sc.strip()
            if "=" in sc:
                name = sc.split("=", 1)[0].strip()
                session_keywords = ["session", "sess", "sid", "token", "auth", "jwt", "phpsessid"]
                if any(kw in name.lower() for kw in session_keywords):
                    cookie_key = ("set", info["src_ip"], info["dst_ip"], name)
                    if cookie_key not in seen_cookies:
                        seen_cookies.add(cookie_key)
                        findings.append({
                            **info,
                            "protocol": "HTTP",
                            "credential_type": "set_cookie",
                            "cookie_name": name,
                            "value_redacted": redact_password(sc.split("=", 1)[1].split(";")[0].strip()),
                            "attributes": sc[len(name) + 1:].strip()[:200],
                            "raw_context": f"Set-Cookie: {sc[:200]}",
                        })

    if verbose and findings:
        print(f"    Found {len(findings)} interesting cookies", file=sys.stderr)

    return findings


def extract_api_keys(packets, verbose=False):
    """Extract API key patterns from HTTP headers and URLs.

    Looks for Authorization: Bearer, api_key=, token=, x-api-key, etc.
    """
    print("  Extracting API keys and tokens...", file=sys.stderr)
    findings = []
    seen = set()

    # Header patterns
    header_patterns = [
        (r"[Aa]uthorization:\s*[Bb]earer\s+(\S+)", "bearer_token"),
        (r"[Xx]-[Aa][Pp][Ii]-[Kk]ey:\s*(\S+)", "x_api_key"),
        (r"[Xx]-[Aa]uth-[Tt]oken:\s*(\S+)", "x_auth_token"),
        (r"[Xx]-[Aa]ccess-[Tt]oken:\s*(\S+)", "x_access_token"),
        (r"[Aa]pi[-_][Kk]ey:\s*(\S+)", "api_key_header"),
    ]

    # URL query parameter patterns
    url_patterns = [
        (r"[?&]api[_-]?key=([^&\s]+)", "api_key_param"),
        (r"[?&]token=([^&\s]+)", "token_param"),
        (r"[?&]access[_-]?token=([^&\s]+)", "access_token_param"),
        (r"[?&]auth[_-]?token=([^&\s]+)", "auth_token_param"),
        (r"[?&]secret=([^&\s]+)", "secret_param"),
        (r"[?&]client[_-]?secret=([^&\s]+)", "client_secret_param"),
    ]

    for pkt in packets:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            continue

        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        # Check common HTTP ports
        if dport not in (80, 8080, 8000, 8888, 3000, 5000, 443, 8443) and \
           sport not in (80, 8080, 8000, 8888, 3000, 5000, 443, 8443):
            continue

        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            continue

        info = get_packet_info(pkt)

        # Check headers
        for pattern, key_type in header_patterns:
            match = re.search(pattern, payload)
            if match:
                value = match.group(1)
                dedup_key = (key_type, info["src_ip"], info["dst_ip"], value[:10])
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append({
                        **info,
                        "protocol": "HTTP",
                        "credential_type": key_type,
                        "value_redacted": redact_password(value),
                        "value_length": len(value),
                        "raw_context": match.group(0)[:200],
                    })

                    if verbose:
                        print(f"    API Key: {key_type} from {info['src_ip']}", file=sys.stderr)

        # Check URL parameters (first line of HTTP request)
        first_line = payload.split("\r\n", 1)[0] if "\r\n" in payload else payload.split("\n", 1)[0]
        for pattern, key_type in url_patterns:
            match = re.search(pattern, first_line)
            if match:
                value = match.group(1)
                dedup_key = (key_type, info["src_ip"], info["dst_ip"], value[:10])
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    findings.append({
                        **info,
                        "protocol": "HTTP",
                        "credential_type": key_type,
                        "value_redacted": redact_password(value),
                        "value_length": len(value),
                        "raw_context": first_line[:200],
                    })

                    if verbose:
                        print(f"    API Key (URL): {key_type} from {info['src_ip']}", file=sys.stderr)

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

    print(f"Analyzing {len(packets)} packets for credentials...", file=sys.stderr)

    result = {
        "capture_file": os.path.basename(config["capture_file"]),
        "total_packets": len(packets),
        "analysis_timestamp": datetime.utcnow().isoformat() + "Z",
        "warning": "Credentials extracted from CLEARTEXT protocols only. Actual passwords are partially redacted.",
        "http_auth": [],
        "http_forms": [],
        "ftp_credentials": [],
        "smtp_auth": [],
        "telnet_credentials": [],
        "cookies": [],
        "api_keys": [],
    }

    extractors = [
        ("http_auth", extract_http_auth),
        ("http_forms", extract_http_forms),
        ("ftp_credentials", extract_ftp_credentials),
        ("smtp_auth", extract_smtp_auth),
        ("telnet_credentials", extract_telnet_credentials),
        ("cookies", extract_cookies),
        ("api_keys", extract_api_keys),
    ]

    for key, func in extractors:
        try:
            result[key] = func(packets, config["verbose"])
        except Exception as e:
            print(f"  Warning: {key} extraction failed: {e}", file=sys.stderr)

    # Summary
    total_findings = sum(len(result[k]) for k, _ in extractors)

    result["summary"] = {
        "total_credentials_found": total_findings,
        "http_auth_count": len(result["http_auth"]),
        "http_forms_count": len(result["http_forms"]),
        "ftp_credentials_count": len(result["ftp_credentials"]),
        "smtp_auth_count": len(result["smtp_auth"]),
        "telnet_credentials_count": len(result["telnet_credentials"]),
        "cookies_count": len(result["cookies"]),
        "api_keys_count": len(result["api_keys"]),
    }

    # Write output
    output_path = os.path.join(config["output_dir"], f"{config['name']}_credentials.json")
    os.makedirs(config["output_dir"], exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\nResults:", file=sys.stderr)
    print(f"  HTTP Auth:              {len(result['http_auth'])}", file=sys.stderr)
    print(f"  HTTP Forms:             {len(result['http_forms'])}", file=sys.stderr)
    print(f"  FTP Credentials:        {len(result['ftp_credentials'])}", file=sys.stderr)
    print(f"  SMTP Auth:              {len(result['smtp_auth'])}", file=sys.stderr)
    print(f"  Telnet Credentials:     {len(result['telnet_credentials'])}", file=sys.stderr)
    print(f"  Cookies:                {len(result['cookies'])}", file=sys.stderr)
    print(f"  API Keys:               {len(result['api_keys'])}", file=sys.stderr)
    print(f"  Total findings:         {total_findings}", file=sys.stderr)
    print(f"Output: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
