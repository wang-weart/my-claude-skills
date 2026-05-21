#!/bin/bash
# Reproduce a crash and capture a trace the classifier understands.
#
# Runs <binary> on <input>, capturing (1) any AddressSanitizer report and
# (2) a debugger backtrace as a fallback, into one trace.txt with the sections
# `=== ASAN output ===` and `=== debugger backtrace ===`.
#
# Usage:
#   reproduce.sh -b <binary> -i <input> [-m file|stdin|atat] [-x "extra args"]
#                [-o <trace.txt>] [--timeout N] [--debugger auto|gdb|lldb|none]
#
# arg modes:
#   atat  (default) — "@@" in extra args is replaced by the input path;
#                     if there is no "@@", the input path is appended last.
#   file            — input path is appended after extra args.
#   stdin           — input is fed on stdin; extra args passed as-is.
# No `set -u`: macOS ships Bash 3.2, where expanding an empty array under -u is
# fatal. We guard variables manually instead.
set -o pipefail

BIN="" INPUT="" MODE="atat" EXTRA="" OUT="" TIMEOUT=60 DBG="auto"

die() { echo "error: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    -b|--binary)   BIN="$2"; shift 2;;
    -i|--input)    INPUT="$2"; shift 2;;
    -m|--arg-mode) MODE="$2"; shift 2;;
    -x|--extra-args) EXTRA="$2"; shift 2;;
    -o|--output)   OUT="$2"; shift 2;;
    --timeout)     TIMEOUT="$2"; shift 2;;
    --debugger)    DBG="$2"; shift 2;;
    -h|--help)     sed -n '2,21p' "$0"; exit 0;;
    *) die "unknown option: $1";;
  esac
done

[ -n "$BIN" ]   || die "missing -b/--binary"
[ -n "$INPUT" ] || die "missing -i/--input"
[ -x "$BIN" ]   || die "binary not executable: $BIN"
[ -f "$INPUT" ] || die "input file not found: $INPUT"
[ -n "$OUT" ]   || OUT="./trace.txt"

# Build the argv (everything after the binary) for the chosen arg mode.
# Built directly as a global array — macOS Bash 3.2 lacks `mapfile`, and an
# array can't be returned from a function anyway. EXTRA is whitespace-split.
EXTRA_ARR=()
# shellcheck disable=SC2206
[ -n "$EXTRA" ] && EXTRA_ARR=($EXTRA)
RUN_ARGS=()
case "$MODE" in
  atat)
    if [[ "$EXTRA" == *"@@"* ]]; then
      for a in "${EXTRA_ARR[@]}"; do
        if [ "$a" = "@@" ]; then RUN_ARGS+=("$INPUT"); else RUN_ARGS+=("$a"); fi
      done
    else
      RUN_ARGS=("${EXTRA_ARR[@]}" "$INPUT")
    fi
    ;;
  file)  RUN_ARGS=("${EXTRA_ARR[@]}" "$INPUT");;
  stdin) RUN_ARGS=("${EXTRA_ARR[@]}");;
  *) die "unknown arg mode: $MODE";;
esac

# A timeout helper that works on Linux (timeout) and macOS (gtimeout, else none).
TO=""
if command -v timeout >/dev/null 2>&1; then TO="timeout ${TIMEOUT}"
elif command -v gtimeout >/dev/null 2>&1; then TO="gtimeout ${TIMEOUT}"; fi

# detect_leaks=0: LeakSanitizer is unsupported on macOS/arm64 and aborts ASAN
# before the target runs. Leaks are low-priority at triage time anyway; the
# classifier still handles LeakSanitizer output if a trace contains it.
ASAN_ENV=(ASAN_OPTIONS="symbolize=1:detect_leaks=0:abort_on_error=0:print_stacktrace=1"
          UBSAN_OPTIONS="print_stacktrace=1")

echo "[*] Running target to capture ASAN/runtime output..." >&2
if [ "$MODE" = stdin ]; then
  ASAN_OUT="$(env "${ASAN_ENV[@]}" $TO "$BIN" "${RUN_ARGS[@]}" < "$INPUT" 2>&1)"
else
  ASAN_OUT="$(env "${ASAN_ENV[@]}" $TO "$BIN" "${RUN_ARGS[@]}" 2>&1)"
fi
RC=$?

# Pick a debugger for the backtrace fallback.
pick_dbg() {
  case "$DBG" in
    none) echo none;;
    gdb)  command -v gdb  >/dev/null 2>&1 && echo gdb  || echo none;;
    lldb) command -v lldb >/dev/null 2>&1 && echo lldb || echo none;;
    auto)
      if command -v gdb  >/dev/null 2>&1; then echo gdb
      elif command -v lldb >/dev/null 2>&1; then echo lldb
      else echo none; fi;;
    *) echo none;;
  esac
}
USE_DBG="$(pick_dbg)"

DBG_OUT=""
case "$USE_DBG" in
  gdb)
    echo "[*] Capturing GDB backtrace..." >&2
    if [ "$MODE" = stdin ]; then
      DBG_OUT="$(gdb -batch -nx -ex "run < $INPUT" -ex "bt" -ex "info registers" \
                   --args "$BIN" "${RUN_ARGS[@]}" 2>&1)"
    else
      DBG_OUT="$(gdb -batch -nx -ex run -ex "bt" -ex "info registers" \
                   --args "$BIN" "${RUN_ARGS[@]}" 2>&1)"
    fi
    ;;
  lldb)
    echo "[*] Capturing LLDB backtrace..." >&2
    if [ "$MODE" = stdin ]; then
      DBG_OUT="$(lldb -b -o "process launch -i $INPUT" -o "bt all" -o "quit" \
                   -- "$BIN" "${RUN_ARGS[@]}" 2>&1)"
    else
      DBG_OUT="$(lldb -b -o "run" -o "bt all" -o "quit" \
                   -- "$BIN" "${RUN_ARGS[@]}" 2>&1)"
    fi
    ;;
  none)
    DBG_OUT="(no debugger available — install gdb or lldb for a backtrace fallback)"
    ;;
esac

{
  echo "=== invocation ==="
  echo "binary:   $BIN"
  echo "input:    $INPUT"
  echo "arg-mode: $MODE"
  echo "argv:     ${RUN_ARGS[*]}"
  echo "exit:     $RC"
  echo "debugger: $USE_DBG"
  echo
  echo "=== ASAN output ==="
  echo "$ASAN_OUT"
  echo
  echo "=== debugger backtrace ==="
  echo "$DBG_OUT"
} > "$OUT"

echo "[+] Trace written to $OUT" >&2
