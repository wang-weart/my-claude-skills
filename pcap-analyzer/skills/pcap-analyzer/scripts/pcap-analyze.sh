#!/bin/bash
# Wrapper script for pcap/pcapng network capture analysis
# Handles environment setup and provides a simpler interface to analysis scripts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYSIS_SCRIPTS="$SCRIPT_DIR/analysis_scripts"

show_help() {
  cat <<'EOF'
Usage: pcap-analyze.sh [options] <capture_file>

Analyze a network capture file (pcap/pcapng) for forensics and reverse engineering.

Options:
  -o, --output <dir>       Output directory for results (default: current dir)
  -s, --script <name>      Analysis script to run (can be repeated)
  -a, --script-args <args> Arguments for the last specified script
  --bpf <filter>           BPF filter to apply before analysis
  --timeout <seconds>      Analysis timeout
  -v, --verbose            Verbose output
  -h, --help               Show this help

Built-in Scripts (use with -s):
  analyze_all.py           Comprehensive first-pass analysis (overview, protocols, endpoints)
  extract_streams.py       Reassemble TCP/UDP streams and export conversations
  extract_dns.py           Extract DNS queries, responses, and domain lists
  extract_http.py          Extract HTTP requests, responses, headers, and bodies
  export_endpoints.py      Map all network endpoints, ports, and connections
  export_statistics.py     Protocol hierarchy, packet sizes, timing statistics
  find_anomalies.py        Detect beaconing, port scans, C2 patterns, tunneling
  extract_credentials.py   Find cleartext passwords, auth headers, tokens
  extract_files.py         Carve transferred files from HTTP, FTP, SMTP, etc.

Examples:
  # Full analysis
  pcap-analyze.sh -s analyze_all.py -o ./output capture.pcap

  # Extract HTTP traffic
  pcap-analyze.sh -s extract_http.py -o ./output capture.pcapng

  # Find anomalies with BPF pre-filter
  pcap-analyze.sh --bpf "tcp" -s find_anomalies.py -o ./output capture.pcap

  # Run multiple scripts
  pcap-analyze.sh -s extract_dns.py -s extract_http.py -o ./output capture.pcap

  # Extract streams for specific host
  pcap-analyze.sh -s extract_streams.py -a "--host 192.168.1.100" -o ./output capture.pcap
EOF
}

# Check prerequisites
check_prerequisites() {
  if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found. Please install Python 3.8+." >&2
    exit 1
  fi

  if ! python3 -c "from scapy.all import *" 2>/dev/null; then
    echo "Error: scapy not found. Install with: pip install scapy" >&2
    exit 1
  fi

  # tshark is optional but recommended
  if command -v tshark &>/dev/null; then
    export PCAP_HAS_TSHARK="true"
    if [[ "$VERBOSE" == true ]]; then
      echo "tshark found: $(tshark --version 2>/dev/null | head -1)"
    fi
  else
    export PCAP_HAS_TSHARK="false"
    echo "Note: tshark not found. Some features will use scapy fallbacks." >&2
    echo "Install Wireshark/tshark for best results." >&2
  fi
}

# Default values
OUTPUT_DIR="."
SCRIPTS=()
SCRIPT_ARGS=()
BPF_FILTER=""
TIMEOUT=""
VERBOSE=false
CAPTURE_FILE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -o | --output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -s | --script)
      SCRIPTS+=("$2")
      shift 2
      ;;
    -a | --script-args)
      if [[ ${#SCRIPTS[@]} -gt 0 ]]; then
        SCRIPT_ARGS+=("$((${#SCRIPTS[@]} - 1)):$2")
      fi
      shift 2
      ;;
    --bpf)
      BPF_FILTER="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    -v | --verbose)
      VERBOSE=true
      shift
      ;;
    -h | --help)
      show_help
      exit 0
      ;;
    -*)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
    *)
      CAPTURE_FILE="$1"
      shift
      ;;
  esac
done

if [[ -z "$CAPTURE_FILE" ]]; then
  echo "Error: No capture file specified" >&2
  show_help
  exit 1
fi

if [[ ! -f "$CAPTURE_FILE" ]]; then
  echo "Error: Capture file not found: $CAPTURE_FILE" >&2
  exit 1
fi

check_prerequisites

# Resolve to absolute path
CAPTURE_FILE="$(cd "$(dirname "$CAPTURE_FILE")" && pwd)/$(basename "$CAPTURE_FILE")"

# Create output directory
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# Export environment for scripts
export PCAP_OUTPUT_DIR="$OUTPUT_DIR"
export PCAP_CAPTURE_FILE="$CAPTURE_FILE"
export PCAP_BPF_FILTER="$BPF_FILTER"
export PCAP_VERBOSE="$VERBOSE"

if [[ -n "$TIMEOUT" ]]; then
  export PCAP_TIMEOUT="$TIMEOUT"
fi

# Run each script
if [[ ${#SCRIPTS[@]} -eq 0 ]]; then
  echo "No scripts specified. Use -s to specify analysis scripts." >&2
  echo "Run with -h for available scripts." >&2
  exit 1
fi

OVERALL_EXIT=0

for i in "${!SCRIPTS[@]}"; do
  script="${SCRIPTS[$i]}"
  script_path="$ANALYSIS_SCRIPTS/$script"

  if [[ ! -f "$script_path" ]]; then
    echo "Error: Script not found: $script" >&2
    echo "Available scripts:" >&2
    ls "$ANALYSIS_SCRIPTS"/*.py 2>/dev/null | xargs -I{} basename {} >&2
    OVERALL_EXIT=1
    continue
  fi

  # Build script arguments
  EXTRA_ARGS=""
  for arg_entry in ${SCRIPT_ARGS[@]+"${SCRIPT_ARGS[@]}"}; do
    idx="${arg_entry%%:*}"
    args="${arg_entry#*:}"
    if [[ "$idx" -eq "$i" ]]; then
      EXTRA_ARGS="$args"
    fi
  done

  if [[ "$VERBOSE" == true ]]; then
    echo "Running: python3 $script_path $CAPTURE_FILE $EXTRA_ARGS"
  fi

  echo "=== Running $script ==="

  if [[ -n "$TIMEOUT" ]]; then
    # shellcheck disable=SC2086
    timeout "$TIMEOUT" python3 "$script_path" "$CAPTURE_FILE" $EXTRA_ARGS
    exit_code=$?
    if [[ $exit_code -eq 124 ]]; then
      echo "Warning: $script timed out after ${TIMEOUT}s" >&2
      OVERALL_EXIT=1
    elif [[ $exit_code -ne 0 ]]; then
      echo "Warning: $script exited with code $exit_code" >&2
      OVERALL_EXIT=1
    fi
  else
    # shellcheck disable=SC2086
    python3 "$script_path" "$CAPTURE_FILE" $EXTRA_ARGS
    exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
      echo "Warning: $script exited with code $exit_code" >&2
      OVERALL_EXIT=1
    fi
  fi
done

echo ""
echo "Analysis complete. Output files in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"

exit "$OVERALL_EXIT"
