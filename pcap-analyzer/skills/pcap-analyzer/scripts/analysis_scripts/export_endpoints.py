#!/usr/bin/env python3
"""Map all network endpoints, ports, connections, and services from a capture.

Produces a comprehensive inventory of every host, connection, and detected
service observed in the capture file.

Output:
  {name}_endpoints.json - hosts, connections, services, subnets
"""

import sys
import os
import json
from collections import defaultdict
from datetime import datetime
from ipaddress import ip_address, ip_network

from scapy.all import *


# Well-known port to service mapping
WELL_KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPC",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    514: "Syslog",
    515: "LPD",
    520: "RIP",
    523: "IBM-DB2",
    554: "RTSP",
    587: "SMTP-Submission",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1434: "MSSQL-Browser",
    1521: "Oracle",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    3306: "MySQL",
    3389: "RDP",
    3478: "STUN",
    4443: "Pharos",
    4500: "IPSec-NAT",
    5060: "SIP",
    5061: "SIP-TLS",
    5222: "XMPP",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-SSL",
    6379: "Redis",
    6443: "Kubernetes-API",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8883: "MQTT-SSL",
    8888: "HTTP-Alt",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    11211: "Memcached",
    27017: "MongoDB",
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


def get_mac(pkt):
    """Extract source MAC address from a packet."""
    if pkt.haslayer(Ether):
        return pkt[Ether].src
    return None


def get_protocol_name(pkt):
    """Determine the highest-level protocol name for a packet."""
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        payload = bytes(pkt[Raw].load)
        if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ",
                                b"OPTIONS ", b"PATCH ", b"HTTP/1.")):
            return "HTTP"
        if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
            return "TLS"
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(IP):
        return f"IP-Proto-{pkt[IP].proto}"
    if pkt.haslayer(IPv6):
        return "IPv6"
    return "Other"


def identify_service(port, proto="TCP"):
    """Look up a well-known service name for a port."""
    svc = WELL_KNOWN_PORTS.get(port)
    if svc:
        return f"{svc}/{proto}"
    return None


def infer_subnets(ip_set):
    """Infer likely subnets from a set of IP addresses."""
    subnets = defaultdict(set)

    for ip_str in ip_set:
        try:
            addr = ip_address(ip_str)
            if addr.is_private:
                # Try common private subnet masks
                if ip_str.startswith("10."):
                    # Class A private - guess /24 or /16
                    parts = ip_str.split(".")
                    net24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    subnets[net24].add(ip_str)
                elif ip_str.startswith("172."):
                    parts = ip_str.split(".")
                    second = int(parts[1])
                    if 16 <= second <= 31:
                        net24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        subnets[net24].add(ip_str)
                elif ip_str.startswith("192.168."):
                    parts = ip_str.split(".")
                    net24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    subnets[net24].add(ip_str)
                elif ip_str.startswith("169.254."):
                    subnets["169.254.0.0/16"].add(ip_str)
            else:
                # Public IPs -- group by /24
                parts = ip_str.split(".")
                if len(parts) == 4:
                    net24 = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    subnets[net24].add(ip_str)
        except ValueError:
            continue

    result = []
    for net_str, members in sorted(subnets.items()):
        try:
            net = ip_network(net_str, strict=False)
            is_private = net.is_private
        except ValueError:
            is_private = False
        result.append({
            "subnet": net_str,
            "hosts_seen": len(members),
            "host_ips": sorted(members),
            "is_private": is_private,
        })

    return result


def main():
    capture_file, output_dir, bpf_filter, verbose, name = parse_env()
    output_path = os.path.join(output_dir, f"{name}_endpoints.json")

    packets = load_packets(capture_file, bpf_filter, verbose)

    # Data structures
    hosts = defaultdict(lambda: {
        "macs": set(),
        "tcp_ports": set(),
        "udp_ports": set(),
        "protocols": set(),
        "first_seen": None,
        "last_seen": None,
        "bytes_sent": 0,
        "bytes_received": 0,
        "packet_count": 0,
    })

    connections = defaultdict(lambda: {
        "packet_count": 0,
        "byte_count": 0,
        "first_seen": None,
        "last_seen": None,
    })

    services_seen = defaultdict(lambda: {
        "port": 0,
        "protocol": "",
        "service": "",
        "client_ips": set(),
        "server_ips": set(),
        "packet_count": 0,
    })

    all_ips = set()

    total = len(packets)
    print("Analyzing endpoints...")

    for i, pkt in enumerate(packets):
        if (i + 1) % 10000 == 0:
            print(f"  Processing packet {i+1}/{total}...")

        ts = float(pkt.time)
        pkt_len = len(pkt)
        proto_name = get_protocol_name(pkt)

        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        all_ips.add(src_ip)
        all_ips.add(dst_ip)

        # Update source host
        h = hosts[src_ip]
        mac = get_mac(pkt)
        if mac:
            h["macs"].add(mac)
        h["protocols"].add(proto_name)
        h["bytes_sent"] += pkt_len
        h["packet_count"] += 1
        if h["first_seen"] is None or ts < h["first_seen"]:
            h["first_seen"] = ts
        if h["last_seen"] is None or ts > h["last_seen"]:
            h["last_seen"] = ts

        # Update destination host
        h2 = hosts[dst_ip]
        h2["protocols"].add(proto_name)
        h2["bytes_received"] += pkt_len
        h2["packet_count"] += 1
        if h2["first_seen"] is None or ts < h2["first_seen"]:
            h2["first_seen"] = ts
        if h2["last_seen"] is None or ts > h2["last_seen"]:
            h2["last_seen"] = ts

        # TCP connections
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport

            hosts[src_ip]["tcp_ports"].add(src_port)
            hosts[dst_ip]["tcp_ports"].add(dst_port)

            conn_key = ("TCP", src_ip, src_port, dst_ip, dst_port)
            c = connections[conn_key]
            c["packet_count"] += 1
            c["byte_count"] += pkt_len
            if c["first_seen"] is None or ts < c["first_seen"]:
                c["first_seen"] = ts
            if c["last_seen"] is None or ts > c["last_seen"]:
                c["last_seen"] = ts

            # Service detection
            for port in (src_port, dst_port):
                svc = identify_service(port, "TCP")
                if svc:
                    s = services_seen[svc]
                    s["port"] = port
                    s["protocol"] = "TCP"
                    s["service"] = svc
                    s["packet_count"] += 1
                    # Heuristic: lower port is the server
                    if port == dst_port:
                        s["server_ips"].add(dst_ip)
                        s["client_ips"].add(src_ip)
                    else:
                        s["server_ips"].add(src_ip)
                        s["client_ips"].add(dst_ip)

        # UDP connections
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport

            hosts[src_ip]["udp_ports"].add(src_port)
            hosts[dst_ip]["udp_ports"].add(dst_port)

            conn_key = ("UDP", src_ip, src_port, dst_ip, dst_port)
            c = connections[conn_key]
            c["packet_count"] += 1
            c["byte_count"] += pkt_len
            if c["first_seen"] is None or ts < c["first_seen"]:
                c["first_seen"] = ts
            if c["last_seen"] is None or ts > c["last_seen"]:
                c["last_seen"] = ts

            for port in (src_port, dst_port):
                svc = identify_service(port, "UDP")
                if svc:
                    s = services_seen[svc]
                    s["port"] = port
                    s["protocol"] = "UDP"
                    s["service"] = svc
                    s["packet_count"] += 1
                    if port == dst_port:
                        s["server_ips"].add(dst_ip)
                        s["client_ips"].add(src_ip)
                    else:
                        s["server_ips"].add(src_ip)
                        s["client_ips"].add(dst_ip)

        # ICMP
        elif pkt.haslayer(ICMP):
            conn_key = ("ICMP", src_ip, 0, dst_ip, 0)
            c = connections[conn_key]
            c["packet_count"] += 1
            c["byte_count"] += pkt_len
            if c["first_seen"] is None or ts < c["first_seen"]:
                c["first_seen"] = ts
            if c["last_seen"] is None or ts > c["last_seen"]:
                c["last_seen"] = ts

    # Build output
    print("Building output...")

    # Hosts
    hosts_out = []
    for ip_str in sorted(hosts.keys()):
        h = hosts[ip_str]
        try:
            addr = ip_address(ip_str)
            is_private = addr.is_private
        except ValueError:
            is_private = False

        hosts_out.append({
            "ip": ip_str,
            "is_private": is_private,
            "mac_addresses": sorted(h["macs"]),
            "tcp_ports": sorted(h["tcp_ports"]),
            "udp_ports": sorted(h["udp_ports"]),
            "protocols": sorted(h["protocols"]),
            "first_seen": datetime.utcfromtimestamp(h["first_seen"]).isoformat() + "Z" if h["first_seen"] else None,
            "last_seen": datetime.utcfromtimestamp(h["last_seen"]).isoformat() + "Z" if h["last_seen"] else None,
            "bytes_sent": h["bytes_sent"],
            "bytes_received": h["bytes_received"],
            "packet_count": h["packet_count"],
        })

    # Connections
    conns_out = []
    for conn_key, c in sorted(connections.items(), key=lambda x: -x[1]["packet_count"]):
        proto, src_ip, src_port, dst_ip, dst_port = conn_key
        duration = 0.0
        if c["first_seen"] is not None and c["last_seen"] is not None:
            duration = round(c["last_seen"] - c["first_seen"], 6)
        conns_out.append({
            "protocol": proto,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "packet_count": c["packet_count"],
            "byte_count": c["byte_count"],
            "duration_seconds": duration,
            "first_seen": datetime.utcfromtimestamp(c["first_seen"]).isoformat() + "Z" if c["first_seen"] else None,
            "last_seen": datetime.utcfromtimestamp(c["last_seen"]).isoformat() + "Z" if c["last_seen"] else None,
        })

    # Services
    services_out = []
    for svc_key in sorted(services_seen.keys()):
        s = services_seen[svc_key]
        services_out.append({
            "service": s["service"],
            "port": s["port"],
            "protocol": s["protocol"],
            "client_ips": sorted(s["client_ips"]),
            "server_ips": sorted(s["server_ips"]),
            "packet_count": s["packet_count"],
        })

    # Subnets
    subnets_out = infer_subnets(all_ips)

    result = {
        "capture_file": os.path.basename(capture_file),
        "total_packets_analyzed": total,
        "unique_hosts": len(hosts_out),
        "unique_connections": len(conns_out),
        "detected_services": len(services_out),
        "inferred_subnets": len(subnets_out),
        "hosts": hosts_out,
        "connections": conns_out,
        "services": services_out,
        "subnets": subnets_out,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"Wrote endpoint analysis to {output_path}")
    print(f"  Hosts: {len(hosts_out)}")
    print(f"  Connections: {len(conns_out)}")
    print(f"  Services: {len(services_out)}")
    print(f"  Subnets: {len(subnets_out)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)
