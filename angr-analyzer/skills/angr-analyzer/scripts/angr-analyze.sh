#!/bin/bash
# Wrapper script for angr binary analysis
# Handles environment setup and provides a simpler interface to analysis scripts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYSIS_SCRIPTS="$SCRIPT_DIR/analysis_scripts"

show_help() {
  cat <<'EOF'
Usage: angr-analyze.sh [options] <binary>

Analyze a binary file using angr's Python framework.

Options:
  -o, --output <dir>       Output directory for results (default: current dir)
  -s, --script <name>      Analysis script to run (can be repeated)
  -a, --script-args <args> Arguments for the last specified script
  --base-addr <addr>       Base address for rebasing (hex, e.g., 0x08000000)
  --auto-load-libs         Load shared library dependencies (default: off)
  --timeout <seconds>      Analysis timeout
  -v, --verbose            Verbose output
  -h, --help               Show this help

Built-in Scripts (use with -s):
  analyze_all.py           Comprehensive analysis (summary, decompile, functions, strings)
  decompile.py             Decompile all functions to C pseudocode
  export_functions.py      Export function list with metadata as JSON
  export_strings.py        Export all strings found in the binary
  export_cfg.py            Export control flow graph as JSON
  export_symbols.py        Export symbols, imports, exports, sections
  export_xrefs.py          Export cross-references between functions
  find_vulns.py            Detect dangerous function patterns
  symbolic_explore.py      Symbolic execution (use -a "--find ADDR --avoid ADDR")

Examples:
  # Full analysis
  angr-analyze.sh -s analyze_all.py -o ./output myprogram

  # Decompile only
  angr-analyze.sh -s decompile.py -o ./output myprogram

  # Symbolic execution to find path to address
  angr-analyze.sh -s symbolic_explore.py -a "--find 0x401234 --avoid 0x401300" binary

  # Run multiple scripts
  angr-analyze.sh -s export_functions.py -s export_strings.py -o ./output binary

  # Analyze firmware with base address
  angr-analyze.sh --base-addr 0x08000000 -s analyze_all.py firmware.bin
EOF
}

# Check prerequisites
check_prerequisites() {
  if ! command -v python3 &>/dev/null; then
    echo "Error: python3 not found. Please install Python 3.8+." >&2
    exit 1
  fi

  if ! python3 -c "import angr" 2>/dev/null; then
    echo "Error: angr not found. Install with: pip install angr" >&2
    exit 1
  fi
}

# Default values
OUTPUT_DIR="."
SCRIPTS=()
SCRIPT_ARGS=()
BASE_ADDR=""
AUTO_LOAD_LIBS="false"
TIMEOUT=""
VERBOSE=false
BINARY=""

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
    --base-addr)
      BASE_ADDR="$2"
      shift 2
      ;;
    --auto-load-libs)
      AUTO_LOAD_LIBS="true"
      shift
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
      BINARY="$1"
      shift
      ;;
  esac
done

if [[ -z "$BINARY" ]]; then
  echo "Error: No binary file specified" >&2
  show_help
  exit 1
fi

if [[ ! -f "$BINARY" ]]; then
  echo "Error: Binary file not found: $BINARY" >&2
  exit 1
fi

check_prerequisites

# Resolve to absolute path
BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"

# Create output directory
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# Export environment for scripts
export ANGR_OUTPUT_DIR="$OUTPUT_DIR"
export ANGR_BINARY="$BINARY"
export ANGR_AUTO_LOAD_LIBS="$AUTO_LOAD_LIBS"
export ANGR_BASE_ADDR="$BASE_ADDR"
export ANGR_VERBOSE="$VERBOSE"

if [[ -n "$TIMEOUT" ]]; then
  export ANGR_TIMEOUT="$TIMEOUT"
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
    echo "Running: python3 $script_path $BINARY $EXTRA_ARGS"
  fi

  echo "=== Running $script ==="

  if [[ -n "$TIMEOUT" ]]; then
    # shellcheck disable=SC2086
    timeout "$TIMEOUT" python3 "$script_path" "$BINARY" $EXTRA_ARGS
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
    python3 "$script_path" "$BINARY" $EXTRA_ARGS
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
