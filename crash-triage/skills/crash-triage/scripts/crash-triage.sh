#!/bin/bash
# Wrapper for crash triage: reproduce a crashing input and classify the result,
# or classify a trace you already have.

# No `set -u`: macOS ships Bash 3.2, where expanding an empty array under -u is
# fatal (the CLS_ARGS array below is often empty). We guard variables manually.
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRIAGE_SCRIPTS="$SCRIPT_DIR/triage_scripts"

show_help() {
  cat <<'EOF'
Usage:
  crash-triage.sh -b <binary> -i <input> [options]   # reproduce + classify
  crash-triage.sh -t <trace-file>                     # classify an existing trace
  cat trace.txt | crash-triage.sh -t -                # classify from stdin

Reproduce options:
  -b, --binary <path>      Target binary (ideally an ASAN+UBSAN build)
  -i, --input <file>       Crashing input / PoC
  -m, --arg-mode <mode>    How input reaches the target (default: atat):
                             atat  - "@@" in extra args -> input path
                                     (appended if no "@@")
                             file  - input path appended after extra args
                             stdin - input fed on stdin
  -x, --extra-args "..."   Extra args for the target (e.g. "-o /dev/null @@")
      --timeout <secs>     Repro timeout (default: 60)
      --debugger <which>   auto | gdb | lldb | none (default: auto)

Classify-only:
  -t, --trace <file>       Classify this trace instead of reproducing ("-" = stdin)

Common:
  -o, --output <dir>       Output dir for trace.txt + verdict.json (default: ./crash-triage-out)
      --label <id>         Identifier (e.g. crash hash) shown in the verdict
      --json               Print JSON verdict only
  -h, --help               Show this help

Examples:
  # Reproduce a poppler crash (pdftotext takes the file as @@) and classify it
  crash-triage.sh -b ./build-asan/pdftotext -i poc.pdf -x "@@ /dev/null"

  # A target that reads stdin
  crash-triage.sh -b ./parser -i crash.bin -m stdin

  # Classify an ASAN log you already captured (no re-run)
  crash-triage.sh -t ci-asan.log --label 7f3a9c

  # Triage a whole directory of PoCs
  for f in crashes/*; do crash-triage.sh -b ./tgt -i "$f" --label "$(basename "$f")"; done
EOF
}

check_prerequisites() {
  command -v python3 >/dev/null 2>&1 || { echo "error: python3 not found" >&2; exit 1; }
}

BIN="" INPUT="" MODE="atat" EXTRA="" TRACE="" OUTDIR="./crash-triage-out"
LABEL="" TIMEOUT=60 DBG="auto" JSON=""

while [ $# -gt 0 ]; do
  case "$1" in
    -b|--binary)     BIN="$2"; shift 2;;
    -i|--input)      INPUT="$2"; shift 2;;
    -m|--arg-mode)   MODE="$2"; shift 2;;
    -x|--extra-args) EXTRA="$2"; shift 2;;
    -t|--trace)      TRACE="$2"; shift 2;;
    -o|--output)     OUTDIR="$2"; shift 2;;
    --label)         LABEL="$2"; shift 2;;
    --timeout)       TIMEOUT="$2"; shift 2;;
    --debugger)      DBG="$2"; shift 2;;
    --json)          JSON="--json"; shift;;
    -h|--help)       show_help; exit 0;;
    *) echo "error: unknown option: $1" >&2; show_help; exit 2;;
  esac
done

check_prerequisites

CLS_ARGS=()
[ -n "$LABEL" ] && CLS_ARGS+=(--label "$LABEL")
[ -n "$JSON" ]  && CLS_ARGS+=(--json)

# Classify-only path: a trace file (or stdin) was provided directly.
if [ -n "$TRACE" ]; then
  if [ "$TRACE" = "-" ]; then
    python3 "$TRIAGE_SCRIPTS/classify_trace.py" - "${CLS_ARGS[@]}"
  else
    [ -f "$TRACE" ] || { echo "error: trace not found: $TRACE" >&2; exit 2; }
    python3 "$TRIAGE_SCRIPTS/classify_trace.py" "$TRACE" "${CLS_ARGS[@]}"
  fi
  exit $?
fi

# Reproduce-then-classify path.
[ -n "$BIN" ]   || { echo "error: need -b/--binary (or -t to classify a trace)" >&2; exit 2; }
[ -n "$INPUT" ] || { echo "error: need -i/--input (or -t to classify a trace)" >&2; exit 2; }

mkdir -p "$OUTDIR"
TRACE_OUT="$OUTDIR/trace.txt"
VERDICT_OUT="$OUTDIR/verdict.json"

bash "$TRIAGE_SCRIPTS/reproduce.sh" \
  -b "$BIN" -i "$INPUT" -m "$MODE" -x "$EXTRA" \
  -o "$TRACE_OUT" --timeout "$TIMEOUT" --debugger "$DBG"

python3 "$TRIAGE_SCRIPTS/classify_trace.py" "$TRACE_OUT" -o "$VERDICT_OUT" "${CLS_ARGS[@]}"
echo
echo "[+] trace:   $TRACE_OUT"
echo "[+] verdict: $VERDICT_OUT"
