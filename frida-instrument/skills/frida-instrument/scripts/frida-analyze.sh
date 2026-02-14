#!/bin/bash
# Wrapper script for Frida dynamic instrumentation
# Handles spawn/attach, script injection, and output collection

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS_DIR="$SCRIPT_DIR/agents"

show_help() {
  cat <<'EOF'
Usage: frida-analyze.sh [options]

Instrument a process using Frida's dynamic analysis toolkit.

Modes (one required):
  --spawn <binary>         Launch binary and instrument it
  --attach <pid_or_name>   Attach to a running process by PID or name

Options:
  -o, --output <dir>       Output directory for results (default: current dir)
  -s, --script <name>      Agent script to run (can be repeated)
  -a, --script-args <json> JSON arguments for the last specified script
  -D, --device <id>        Device ID (for remote/USB devices)
  -U, --usb                Use USB-connected device
  --no-pause               Don't pause spawned process
  --timeout <seconds>      Script timeout (default: no timeout)
  -v, --verbose            Verbose output
  -h, --help               Show this help

Built-in Agent Scripts (use with -s):
  enumerate_all.js         Comprehensive process enumeration
  enumerate_modules.js     List loaded modules
  enumerate_exports.js     List module exports
  enumerate_imports.js     List module imports
  trace_calls.js           Trace function calls with args/retvals
  hook_functions.js        Hook and modify function behavior
  dump_memory.js           Dump memory regions
  scan_memory.js           Scan memory for patterns
  stalker_trace.js         Instruction-level code tracing

Examples:
  # Enumerate everything from a spawned process
  frida-analyze.sh --spawn ./myapp -s enumerate_all.js -o ./output

  # Trace calls in a running process
  frida-analyze.sh --attach 1234 -s trace_calls.js -a '{"functions":["open","read"]}'

  # Scan memory for a string
  frida-analyze.sh --attach myapp -s scan_memory.js -a '{"string":"password"}'

  # Stalker trace on USB device
  frida-analyze.sh -U --attach myapp -s stalker_trace.js -a '{"function":"main"}'
EOF
}

# Check prerequisites
check_prerequisites() {
  if ! command -v frida &>/dev/null; then
    echo "Error: frida not found. Install with: pip install frida-tools" >&2
    exit 1
  fi
}

# Default values
OUTPUT_DIR="."
SCRIPTS=()
SCRIPT_ARGS_MAP=()
DEVICE_ARGS=""
SPAWN_TARGET=""
ATTACH_TARGET=""
NO_PAUSE=false
TIMEOUT=""
VERBOSE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --spawn)
      SPAWN_TARGET="$2"
      shift 2
      ;;
    --attach)
      ATTACH_TARGET="$2"
      shift 2
      ;;
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
        SCRIPT_ARGS_MAP+=("$((${#SCRIPTS[@]} - 1)):$2")
      fi
      shift 2
      ;;
    -D | --device)
      DEVICE_ARGS="-D $2"
      shift 2
      ;;
    -U | --usb)
      DEVICE_ARGS="-U"
      shift
      ;;
    --no-pause)
      NO_PAUSE=true
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
      echo "Unknown argument: $1. Use --spawn or --attach." >&2
      exit 1
      ;;
  esac
done

# Validate mode
if [[ -z "$SPAWN_TARGET" && -z "$ATTACH_TARGET" ]]; then
  echo "Error: Must specify --spawn <binary> or --attach <pid_or_name>" >&2
  show_help
  exit 1
fi

if [[ -n "$SPAWN_TARGET" && -n "$ATTACH_TARGET" ]]; then
  echo "Error: Cannot use both --spawn and --attach" >&2
  exit 1
fi

if [[ ${#SCRIPTS[@]} -eq 0 ]]; then
  echo "Error: No scripts specified. Use -s to specify agent scripts." >&2
  exit 1
fi

check_prerequisites

# Create output directory
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"

# Determine process name for output files
if [[ -n "$SPAWN_TARGET" ]]; then
  PROCESS_NAME="$(basename "$SPAWN_TARGET" | sed 's/\.[^.]*$//')"
else
  PROCESS_NAME="$ATTACH_TARGET"
  # If it's a PID, try to get the process name
  if [[ "$ATTACH_TARGET" =~ ^[0-9]+$ ]]; then
    PROC_CMD=$(ps -p "$ATTACH_TARGET" -o comm= 2>/dev/null || echo "pid_$ATTACH_TARGET")
    PROCESS_NAME="$(basename "$PROC_CMD")"
  fi
fi

OVERALL_EXIT=0

for i in "${!SCRIPTS[@]}"; do
  script="${SCRIPTS[$i]}"
  script_path="$AGENTS_DIR/$script"

  if [[ ! -f "$script_path" ]]; then
    echo "Error: Script not found: $script" >&2
    echo "Available scripts:" >&2
    ls "$AGENTS_DIR"/*.js 2>/dev/null | xargs -I{} basename {} >&2
    OVERALL_EXIT=1
    continue
  fi

  # Get script args for this script
  SCRIPT_ARGS="{}"
  for arg_entry in ${SCRIPT_ARGS_MAP[@]+"${SCRIPT_ARGS_MAP[@]}"}; do
    idx="${arg_entry%%:*}"
    args="${arg_entry#*:}"
    if [[ "$idx" -eq "$i" ]]; then
      SCRIPT_ARGS="$args"
    fi
  done

  echo "=== Running $script ==="

  # Create a combined script that injects config globals then loads the agent
  TEMP_SCRIPT=$(mktemp /tmp/frida_combined_XXXXXX.js)
  cat > "$TEMP_SCRIPT" <<JSEOF
// Injected configuration
var __frida_output_dir = ${OUTPUT_DIR@Q};
var __frida_process_name = ${PROCESS_NAME@Q};
var __frida_script_args = $SCRIPT_ARGS;
var __frida_verbose = $( [[ "$VERBOSE" == true ]] && echo "true" || echo "false" );

// Helper: write JSON to output file
function __writeOutput(filename, data) {
    var path = __frida_output_dir + '/' + filename;
    var f = new File(path, 'w');
    f.write(JSON.stringify(data, null, 2));
    f.flush();
    f.close();
    console.log('[*] Output written to: ' + path);
}

// Helper: write raw string to output file
function __writeRawOutput(filename, text) {
    var path = __frida_output_dir + '/' + filename;
    var f = new File(path, 'w');
    f.write(text);
    f.flush();
    f.close();
    console.log('[*] Output written to: ' + path);
}

// Helper: write binary to output file
function __writeBinaryOutput(filename, bytes) {
    var path = __frida_output_dir + '/' + filename;
    var f = new File(path, 'wb');
    f.write(bytes);
    f.flush();
    f.close();
    console.log('[*] Binary output written to: ' + path);
}

JSEOF

  # Append the actual agent script
  cat "$script_path" >> "$TEMP_SCRIPT"

  # Build frida command
  CMD=(frida)

  # Add device args
  if [[ -n "$DEVICE_ARGS" ]]; then
    # shellcheck disable=SC2206
    CMD+=($DEVICE_ARGS)
  fi

  # Add target
  if [[ -n "$SPAWN_TARGET" ]]; then
    CMD+=(-f "$SPAWN_TARGET")
    if [[ "$NO_PAUSE" == true ]]; then
      CMD+=(--no-pause)
    fi
  else
    if [[ "$ATTACH_TARGET" =~ ^[0-9]+$ ]]; then
      CMD+=(-p "$ATTACH_TARGET")
    else
      CMD+=(-n "$ATTACH_TARGET")
    fi
  fi

  CMD+=(-l "$TEMP_SCRIPT" --no-pause -q)

  if [[ "$VERBOSE" == true ]]; then
    echo "Running: ${CMD[*]}"
  fi

  # Run with optional timeout
  if [[ -n "$TIMEOUT" ]]; then
    timeout "$TIMEOUT" "${CMD[@]}" 2>&1 | tee "$OUTPUT_DIR/frida_output.log" || true
    exit_code=${PIPESTATUS[0]}
    if [[ $exit_code -eq 124 ]]; then
      echo "Script timed out after ${TIMEOUT}s (this is often expected for tracing)" >&2
    fi
  else
    "${CMD[@]}" 2>&1 | tee "$OUTPUT_DIR/frida_output.log" || true
  fi

  # Cleanup temp script
  rm -f "$TEMP_SCRIPT"
done

echo ""
echo "Analysis complete. Output files in: $OUTPUT_DIR"
ls -la "$OUTPUT_DIR"

exit "$OVERALL_EXIT"
