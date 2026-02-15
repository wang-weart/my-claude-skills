---
name: pcap-analyzer
description: >-
  Analyzes network captures (pcap/pcapng) for digital forensics and reverse
  engineering. Use when examining packet captures, extracting network artifacts,
  investigating incidents, analyzing malware C2 traffic, or reconstructing
  network activity from capture files.
---

# Pcap Network Capture Analysis

Perform automated network traffic analysis on pcap/pcapng files using scapy.
Extract streams, DNS, HTTP, credentials, and files. Detect anomalies like
beaconing, port scanning, C2 patterns, and data exfiltration.

## When to Use

- Analyzing packet captures from incident response or forensic investigations
- Extracting network artifacts (files, credentials, DNS queries) from pcaps
- Detecting C2 beaconing, port scanning, or data exfiltration patterns
- Reconstructing HTTP sessions and downloaded files from captures
- Mapping network endpoints and communication patterns
- Analyzing malware network behavior from sandbox captures
- CTF challenges involving network forensics
- Investigating cleartext credential exposure in network traffic

## When NOT to Use

- Live traffic capture — use tcpdump, Wireshark, or tshark directly
- Need Wireshark GUI features — open the pcap in Wireshark
- Analyzing encrypted TLS content — need SSLKEYLOGFILE and tshark
- NetFlow/IPFIX data — use flow analysis tools (nfdump, SiLK)
- Wireless-specific analysis (802.11) — use Aircrack-ng suite
- IDS/IPS rule matching — use Suricata or Snort

## Quick Reference

| Task | Command |
|------|---------|
| Full analysis | `{baseDir}/scripts/pcap-analyze.sh -s analyze_all.py -o ./output capture.pcap` |
| Extract TCP/UDP streams | `{baseDir}/scripts/pcap-analyze.sh -s extract_streams.py -o ./output capture.pcap` |
| Extract DNS queries | `{baseDir}/scripts/pcap-analyze.sh -s extract_dns.py -o ./output capture.pcap` |
| Extract HTTP traffic | `{baseDir}/scripts/pcap-analyze.sh -s extract_http.py -o ./output capture.pcap` |
| Map endpoints | `{baseDir}/scripts/pcap-analyze.sh -s export_endpoints.py -o ./output capture.pcap` |
| Traffic statistics | `{baseDir}/scripts/pcap-analyze.sh -s export_statistics.py -o ./output capture.pcap` |
| Detect anomalies | `{baseDir}/scripts/pcap-analyze.sh -s find_anomalies.py -o ./output capture.pcap` |
| Find credentials | `{baseDir}/scripts/pcap-analyze.sh -s extract_credentials.py -o ./output capture.pcap` |
| Carve files | `{baseDir}/scripts/pcap-analyze.sh -s extract_files.py -o ./output capture.pcap` |

## Prerequisites

- **Python 3.8+** with pip
- **scapy**: `pip install scapy`
- **tshark** (optional, recommended): Install Wireshark (`brew install wireshark` / `apt install tshark`)

## Main Wrapper Script

```bash
{baseDir}/scripts/pcap-analyze.sh [options] <capture_file>
```

**Options:**
- `-o, --output <dir>` — Output directory for results (default: current dir)
- `-s, --script <name>` — Analysis script to run (can be repeated)
- `-a, --script-args <args>` — Arguments for the last specified script
- `--bpf <filter>` — BPF filter to apply before analysis
- `--timeout <seconds>` — Analysis timeout
- `-v, --verbose` — Verbose output
- `-h, --help` — Show help

## Built-in Analysis Scripts

### analyze_all.py

Comprehensive first-pass analysis. Best for initial triage of unknown captures.

**Output files:**
- `{name}_summary.txt` — Capture overview: packet count, time range, duration, data rates
- `{name}_protocols.json` — Protocol distribution by layer
- `{name}_endpoints.json` — Top talkers by packet and byte count
- `{name}_conversations.json` — Top IP-pair conversations
- `{name}_interesting.txt` — Notable findings categorized as cleartext protocols, unusual ports, large transfers, suspicious DNS, tunneling indicators

### extract_streams.py

Reassemble TCP and UDP streams. Pass `--host <ip>` or `--port <port>` to
filter, `--max-streams <n>` to limit output.

**Output:** `{name}_streams.json` + `{name}_stream_{n}.bin` per stream

### extract_dns.py

Extract all DNS queries and responses with full record detail.

**Output:**
- `{name}_dns.json` — Queries, responses, record types, TTLs
- `{name}_domains.txt` — Unique domains queried
- `{name}_dns_timeline.json` — Temporal query analysis

### extract_http.py

Extract HTTP transactions from raw TCP payloads. Handles chunked
transfer encoding.

**Output:** `{name}_http.json` + `{name}_http_bodies/` directory

### export_endpoints.py

Map all network endpoints with service identification. Includes MAC
addresses, ports, protocols, subnets, and connection 5-tuples.

**Output:** `{name}_endpoints.json`

### export_statistics.py

Detailed traffic statistics: protocol hierarchy, packet size distribution,
timing analysis, TCP flag distribution, TTL distribution with OS
fingerprint hints.

**Output:** `{name}_statistics.json`

### find_anomalies.py

Detect suspicious patterns: C2 beaconing (low coefficient of variation in
connection intervals), port scanning, data exfiltration, DNS tunneling
(high-entropy long subdomain labels), unusual protocol usage, cleartext
sensitive data, and TLS anomalies.

**Output:** `{name}_anomalies.json`

### extract_credentials.py

Find cleartext credentials: HTTP Basic/Digest auth, form POST data, FTP
USER/PASS, SMTP AUTH, Telnet logins, session cookies, API keys.
Passwords are partially redacted in output.

**Output:** `{name}_credentials.json`

### extract_files.py

Carve files from HTTP responses, FTP transfers, SMTP attachments, and
magic-byte detection in TCP streams. Computes MD5 hashes. Supports
PDF, ZIP, PNG, JPEG, PE, ELF, GIF, GZIP, and more.

**Output:** `{name}_files.json` + `{name}_extracted/` directory

## Common Workflows

### Triage an Unknown Capture

```bash
mkdir -p ./analysis
{baseDir}/scripts/pcap-analyze.sh -s analyze_all.py -o ./analysis capture.pcap
cat ./analysis/capture_summary.txt
cat ./analysis/capture_interesting.txt
```

### Investigate Suspected C2 Traffic

```bash
{baseDir}/scripts/pcap-analyze.sh -s find_anomalies.py -o ./c2 capture.pcap
{baseDir}/scripts/pcap-analyze.sh -s extract_dns.py -o ./c2 capture.pcap
cat ./c2/capture_anomalies.json | jq '.beaconing'
cat ./c2/capture_anomalies.json | jq '.data_exfiltration'
```

### Extract Files from HTTP Traffic

```bash
{baseDir}/scripts/pcap-analyze.sh -s extract_http.py -s extract_files.py -o ./files capture.pcap
cat ./files/capture_files.json | jq '.[].filename'
ls ./files/capture_extracted/
```

### Credential Exposure Audit

```bash
{baseDir}/scripts/pcap-analyze.sh -s extract_credentials.py -o ./creds capture.pcap
cat ./creds/capture_credentials.json | jq 'to_entries | map(select(.value | length > 0))'
```

### Network Forensics (Full Workflow)

```bash
mkdir -p ./forensics
{baseDir}/scripts/pcap-analyze.sh \
    -s analyze_all.py \
    -s export_endpoints.py \
    -s extract_dns.py \
    -s find_anomalies.py \
    -s extract_credentials.py \
    -s extract_files.py \
    -o ./forensics evidence.pcap
```

### Filter Analysis to Specific Host

```bash
{baseDir}/scripts/pcap-analyze.sh \
    --bpf "host 192.168.1.100" \
    -s analyze_all.py \
    -o ./host_analysis capture.pcap

{baseDir}/scripts/pcap-analyze.sh \
    -s extract_streams.py \
    -a "--host 192.168.1.100" \
    -o ./host_analysis capture.pcap
```

## Troubleshooting

### scapy Not Installed

```bash
pip install scapy
```

### Large Capture Files

For captures over 100MB, use BPF filters to narrow scope:
```bash
{baseDir}/scripts/pcap-analyze.sh --bpf "tcp port 80" -s extract_http.py capture.pcap
```

Or use individual scripts instead of analyze_all.py.

### Permission Errors Reading Pcap

```bash
chmod 644 capture.pcap
# Or run with sudo if needed
```

### tshark Not Found

tshark is optional. All scripts work with scapy alone. For best results:
```bash
# macOS
brew install wireshark

# Debian/Ubuntu
sudo apt install tshark

# Fedora/RHEL
sudo dnf install wireshark-cli
```

## Tips

1. **Start with analyze_all.py** — gives a full overview for triage
2. **BPF filters reduce noise** — use `--bpf` to focus on specific hosts or protocols
3. **Use jq for JSON** — all JSON exports are designed for machine processing
4. **Combine with angr/Frida** — extract a binary from pcap, then analyze with angr or trace with Frida
5. **Large pcaps** — filter first, analyze second; scapy loads entire capture into memory
6. **Credentials are redacted** — extract_credentials.py partially masks passwords for safe reporting
