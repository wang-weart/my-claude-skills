#!/usr/bin/env python3
"""DNS query and response extraction from network captures.

Parses all DNS traffic (DNSQR / DNSRR layers) and produces structured
output for analysis.

Produces:
  {name}_dns.json           - All DNS queries and responses with full detail
  {name}_domains.txt        - Unique domains queried (sorted alphabetically)
  {name}_dns_timeline.json  - DNS queries over time for temporal analysis
"""

import sys
import os
import json
import time
from collections import defaultdict, OrderedDict
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
# DNS type / class name helpers
# ---------------------------------------------------------------------------

# Standard DNS query types
DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 36: "KX",
    37: "CERT", 38: "A6", 39: "DNAME", 41: "OPT", 43: "DS",
    44: "SSHFP", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY",
    50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 55: "HIP",
    59: "CDS", 60: "CDNSKEY", 64: "SVCB", 65: "HTTPS",
    99: "SPF", 255: "ANY", 256: "URI", 257: "CAA",
}

DNS_RCODES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
    4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
    8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE",
}


def qtype_name(qtype):
    """Return human-readable query type name."""
    return DNS_QTYPES.get(qtype, f"TYPE{qtype}")


def rcode_name(rcode):
    """Return human-readable response code name."""
    return DNS_RCODES.get(rcode, f"RCODE{rcode}")


def safe_decode(value):
    """Safely decode bytes to string."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").rstrip(".")
    if isinstance(value, str):
        return value.rstrip(".")
    return str(value)


# ---------------------------------------------------------------------------
# DNS record extraction
# ---------------------------------------------------------------------------

def extract_rr_data(rr):
    """Extract data from a single DNS resource record."""
    record = {
        "name": safe_decode(rr.rrname) if hasattr(rr, "rrname") else "",
        "type": qtype_name(rr.type) if hasattr(rr, "type") else "UNKNOWN",
        "type_num": rr.type if hasattr(rr, "type") else 0,
        "ttl": rr.ttl if hasattr(rr, "ttl") else 0,
    }

    rtype = rr.type if hasattr(rr, "type") else 0

    try:
        if rtype == 1:  # A
            record["data"] = rr.rdata if hasattr(rr, "rdata") else str(rr)
        elif rtype == 28:  # AAAA
            record["data"] = rr.rdata if hasattr(rr, "rdata") else str(rr)
        elif rtype == 5:  # CNAME
            record["data"] = safe_decode(rr.rdata) if hasattr(rr, "rdata") else ""
        elif rtype == 2:  # NS
            record["data"] = safe_decode(rr.rdata) if hasattr(rr, "rdata") else ""
        elif rtype == 15:  # MX
            record["data"] = safe_decode(rr.rdata) if hasattr(rr, "rdata") else ""
            if hasattr(rr, "preference"):
                record["preference"] = rr.preference
        elif rtype == 12:  # PTR
            record["data"] = safe_decode(rr.rdata) if hasattr(rr, "rdata") else ""
        elif rtype == 16:  # TXT
            if hasattr(rr, "rdata"):
                rdata = rr.rdata
                if isinstance(rdata, list):
                    record["data"] = [safe_decode(r) for r in rdata]
                else:
                    record["data"] = safe_decode(rdata)
            else:
                record["data"] = ""
        elif rtype == 6:  # SOA
            record["data"] = safe_decode(rr.rdata) if hasattr(rr, "rdata") else str(rr)
        elif rtype == 33:  # SRV
            record["data"] = safe_decode(rr.rdata) if hasattr(rr, "rdata") else ""
            if hasattr(rr, "priority"):
                record["priority"] = rr.priority
            if hasattr(rr, "weight"):
                record["weight"] = rr.weight
            if hasattr(rr, "port"):
                record["srv_port"] = rr.port
        else:
            # Generic fallback
            if hasattr(rr, "rdata"):
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    record["data"] = rdata.hex()
                else:
                    record["data"] = safe_decode(rdata)
            else:
                record["data"] = ""
    except Exception:
        record["data"] = ""

    return record


# ---------------------------------------------------------------------------
# Main DNS extraction
# ---------------------------------------------------------------------------

def extract_dns(packets, name):
    """Parse all DNS packets and produce output files."""
    verbose = is_verbose()

    dns_entries = []      # Full query/response records
    all_domains = set()   # Unique queried domains
    timeline_data = []    # (timestamp, domain, qtype, is_response)

    query_count = 0
    response_count = 0

    print(f"  Scanning {len(packets):,} packets for DNS traffic...")

    for i, pkt in enumerate(packets):
        if verbose and (i + 1) % 10000 == 0:
            print(f"    Processed {i + 1:,} / {len(packets):,} packets")

        if not pkt.haslayer(DNS):
            continue

        dns_layer = pkt[DNS]
        ts = float(pkt.time) if hasattr(pkt, "time") else 0
        ts_str = datetime.fromtimestamp(ts).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        ) if ts > 0 else "N/A"

        # Source and destination IPs
        src_ip = dst_ip = ""
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        # Source/dest ports
        src_port = dst_port = 0
        if pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport

        # DNS transaction ID
        txn_id = dns_layer.id if hasattr(dns_layer, "id") else 0

        # Determine if this is a query (QR=0) or response (QR=1)
        is_response = bool(dns_layer.qr) if hasattr(dns_layer, "qr") else False

        # Extract query section
        queries = []
        if dns_layer.qdcount and dns_layer.qdcount > 0:
            qd = dns_layer.qd
            while qd and not isinstance(qd, NoPayload):
                qname = safe_decode(qd.qname) if hasattr(qd, "qname") else ""
                qt = qd.qtype if hasattr(qd, "qtype") else 0
                queries.append({
                    "name": qname,
                    "type": qtype_name(qt),
                    "type_num": qt,
                })
                if qname:
                    all_domains.add(qname)
                    timeline_data.append((ts, qname, qtype_name(qt), is_response))
                # Move to next query record
                qd = qd.payload if hasattr(qd, "payload") else None
                if isinstance(qd, NoPayload):
                    break

        # Extract answer records
        answers = []
        if is_response and dns_layer.ancount and dns_layer.ancount > 0:
            an = dns_layer.an
            count = 0
            while an and not isinstance(an, NoPayload) and count < dns_layer.ancount:
                try:
                    answers.append(extract_rr_data(an))
                except Exception:
                    pass
                an = an.payload if hasattr(an, "payload") else None
                if isinstance(an, NoPayload):
                    break
                count += 1

        # Extract authority records
        authorities = []
        if is_response and dns_layer.nscount and dns_layer.nscount > 0:
            ns = dns_layer.ns
            count = 0
            while ns and not isinstance(ns, NoPayload) and count < dns_layer.nscount:
                try:
                    authorities.append(extract_rr_data(ns))
                except Exception:
                    pass
                ns = ns.payload if hasattr(ns, "payload") else None
                if isinstance(ns, NoPayload):
                    break
                count += 1

        # Extract additional records
        additionals = []
        if is_response and dns_layer.arcount and dns_layer.arcount > 0:
            ar = dns_layer.ar
            count = 0
            while ar and not isinstance(ar, NoPayload) and count < dns_layer.arcount:
                try:
                    # Skip OPT pseudo-records (EDNS)
                    if hasattr(ar, "type") and ar.type == 41:
                        pass
                    else:
                        additionals.append(extract_rr_data(ar))
                except Exception:
                    pass
                ar = ar.payload if hasattr(ar, "payload") else None
                if isinstance(ar, NoPayload):
                    break
                count += 1

        # Response code
        rcode = dns_layer.rcode if hasattr(dns_layer, "rcode") else 0

        entry = {
            "timestamp": ts_str,
            "timestamp_epoch": round(ts, 6),
            "transaction_id": txn_id,
            "is_response": is_response,
            "source_ip": src_ip,
            "source_port": src_port,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "queries": queries,
        }

        if is_response:
            entry["response_code"] = rcode_name(rcode)
            entry["response_code_num"] = rcode
            entry["answers"] = answers
            entry["authorities"] = authorities
            entry["additionals"] = additionals
            response_count += 1
        else:
            query_count += 1

        dns_entries.append(entry)

    print(f"  Found {query_count} queries and {response_count} responses")
    print(f"  {len(all_domains)} unique domains")

    # -----------------------------------------------------------------------
    # Write {name}_dns.json
    # -----------------------------------------------------------------------
    dns_path = get_output_path(name, "_dns.json")
    print(f"  Writing DNS records to {os.path.basename(dns_path)}")

    with open(dns_path, "w") as f:
        json.dump({
            "summary": {
                "total_dns_packets": len(dns_entries),
                "queries": query_count,
                "responses": response_count,
                "unique_domains": len(all_domains),
            },
            "records": dns_entries,
        }, f, indent=2)

    # -----------------------------------------------------------------------
    # Write {name}_domains.txt
    # -----------------------------------------------------------------------
    domains_path = get_output_path(name, "_domains.txt")
    print(f"  Writing unique domains to {os.path.basename(domains_path)}")

    sorted_domains = sorted(all_domains, key=str.lower)
    with open(domains_path, "w") as f:
        for domain in sorted_domains:
            f.write(domain + "\n")

    # -----------------------------------------------------------------------
    # Write {name}_dns_timeline.json
    # -----------------------------------------------------------------------
    timeline_path = get_output_path(name, "_dns_timeline.json")
    print(f"  Writing DNS timeline to {os.path.basename(timeline_path)}")

    # Group queries into time buckets (1-second granularity)
    buckets = defaultdict(lambda: {"queries": 0, "responses": 0, "domains": []})

    for ts, domain, qtype, is_resp in timeline_data:
        bucket_key = int(ts)
        if is_resp:
            buckets[bucket_key]["responses"] += 1
        else:
            buckets[bucket_key]["queries"] += 1
        # Only store unique domains per bucket, cap at 50 per bucket
        if domain not in buckets[bucket_key]["domains"]:
            if len(buckets[bucket_key]["domains"]) < 50:
                buckets[bucket_key]["domains"].append(domain)

    # Also build a per-domain timeline
    domain_timeline = defaultdict(list)
    for ts, domain, qtype, is_resp in timeline_data:
        if not is_resp:  # Only track queries for the domain timeline
            domain_timeline[domain].append({
                "timestamp": round(ts, 6),
                "type": qtype,
            })

    # Sort buckets by time
    sorted_buckets = []
    for bucket_ts in sorted(buckets.keys()):
        info = buckets[bucket_ts]
        sorted_buckets.append({
            "timestamp": datetime.fromtimestamp(bucket_ts).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "timestamp_epoch": bucket_ts,
            "queries": info["queries"],
            "responses": info["responses"],
            "domains": info["domains"],
        })

    # Top queried domains
    domain_query_counts = defaultdict(int)
    for ts, domain, qtype, is_resp in timeline_data:
        if not is_resp:
            domain_query_counts[domain] += 1

    top_domains = sorted(
        domain_query_counts.items(), key=lambda x: x[1], reverse=True
    )[:50]

    timeline_output = {
        "time_buckets": sorted_buckets,
        "top_queried_domains": [
            {"domain": d, "query_count": c} for d, c in top_domains
        ],
        "domain_timelines": {
            domain: entries[:200]
            for domain, entries in sorted(
                domain_timeline.items(),
                key=lambda x: len(x[1]),
                reverse=True,
            )[:30]
        },
    }

    with open(timeline_path, "w") as f:
        json.dump(timeline_output, f, indent=2)

    return len(dns_entries)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("Usage: extract_dns.py <capture_file>", file=sys.stderr)
        sys.exit(1)

    capture_file = sys.argv[1]
    name = os.path.splitext(os.path.basename(capture_file))[0]

    print(f"=== DNS extraction ===")
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
        # Write empty outputs
        dns_path = get_output_path(name, "_dns.json")
        with open(dns_path, "w") as f:
            json.dump({"summary": {"total_dns_packets": 0, "queries": 0,
                                   "responses": 0, "unique_domains": 0},
                        "records": []}, f, indent=2)
        domains_path = get_output_path(name, "_domains.txt")
        with open(domains_path, "w") as f:
            pass
        timeline_path = get_output_path(name, "_dns_timeline.json")
        with open(timeline_path, "w") as f:
            json.dump({"time_buckets": [], "top_queried_domains": [],
                        "domain_timelines": {}}, f, indent=2)
        sys.exit(0)

    try:
        dns_count = extract_dns(packets, name)
    except Exception as e:
        print(f"Error during DNS extraction: {e}", file=sys.stderr)
        sys.exit(1)

    elapsed = time.time() - start_time
    print(f"\n=== DNS extraction complete ({elapsed:.1f}s) ===")
    print(f"  Processed {dns_count} DNS packets")


if __name__ == "__main__":
    main()
