#!/usr/bin/env python3
"""Classify a crash trace by bug class, severity, and recommended action.

Reads an AddressSanitizer report and/or a GDB/LLDB backtrace (the kind written
by reproduce.sh, or any log you already have) from a file or stdin, then emits a
single verdict: class, severity, the meaningful top frame, and what to do next.

Pure stdlib — no dependencies. Works on a trace you already captured (e.g. from
CI logs or a fuzzer's crashes dir) without re-running anything.
"""
import argparse
import json
import re
import sys

# Sanitizer/runtime/allocator/abort-path frames that are never the *meaningful*
# top frame — skip them when picking the frame to report so the verdict points
# at application code rather than at raise()/malloc()/the ASAN interceptor.
_FRAME_NOISE = re.compile(
    r"__asan|__lsan|__ubsan|__interceptor|__sanitizer|\basan_|"
    r"__libc_start|__libc_message|\b_start\b|__gmon|"
    r"__gi_raise|__gi_abort|__pthread_kill|gsignal|"
    r"__assert_fail|__assert_perror_fail|__chk_fail|__fortify_fail|"
    r"\babort\s*\(|\braise\s*\(|"
    r"\bmalloc\b|\bcalloc\b|\brealloc\b|\bfree\b|operator new|operator delete|"
    r"<null>",
    re.IGNORECASE,
)

# ASAN error tokens that mean a genuine memory-safety bug.
_ASAN_MEMORY_BUGS = (
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "heap-use-after-free",
    "stack-use-after-return",
    "stack-use-after-scope",
    "use-after-poison",
    "container-overflow",
    "dynamic-stack-buffer-overflow",
    "negative-size-param",
    "alloc-dealloc-mismatch",
    "allocation-size-too-big",
    "calloc-overflow",
    "double-free",
    "bad-free",
    "attempting-free-on-address",
    "intra-object-overflow",
)


def _meaningful_top_frame(lines):
    """Pick the first stack frame that points at application code.

    Handles three backtrace dialects:
      ASAN  : ``#0 0x... in func file:line``
      GDB   : ``#0  0x... in func (args) at file:line``  /  ``#0  func () at file:line``
      LLDB  : ``frame #0: 0x... binary`func at file:line:col``
    Returns ``"func at file:line"`` or a raw frame string, else None.
    """
    frame_lines = [
        ln.strip()
        for ln in lines
        if re.match(r"\s*#\d+\s", ln) or "frame #" in ln
    ]
    fallback = None
    for ln in frame_lines:
        if fallback is None:
            fallback = ln
        if _FRAME_NOISE.search(ln):
            continue
        # ASAN / GDB: "... in <func> ... at? <file>:<line>"
        m = re.search(r"\bin\s+([^\s(]+).*?(?:at\s+)?([^\s(]+:\d+)", ln)
        if m:
            return f"{m.group(1)} at {m.group(2)}"
        # GDB without "in": "#0  func (..) at file:line"
        m = re.search(r"#\d+\s+([A-Za-z_][\w:]*)\s*\(.*?\)\s+at\s+(\S+:\d+)", ln)
        if m:
            return f"{m.group(1)} at {m.group(2)}"
        # LLDB: "frame #0: 0x.. binary`func at file:line"
        m = re.search(r"`([^\s(]+).*?\s+at\s+(\S+:\d+)", ln)
        if m:
            return f"{m.group(1)} at {m.group(2)}"
        # LLDB without source: "frame #0: 0x.. binary`func + 12"
        m = re.search(r"`([^\s(]+)", ln)
        if m:
            return m.group(1)
    return fallback


def _segv_address(text):
    """Extract the faulting address from an ASAN SEGV or debugger report."""
    m = re.search(r"unknown address\s+0x([0-9a-fA-F]+)", text)
    if not m:
        m = re.search(r"address\s+0x([0-9a-fA-F]+)", text)
    return int(m.group(1), 16) if m else None


def classify(text):
    """Return a verdict dict for the given trace text."""
    low = text.lower()
    top = _meaningful_top_frame(text.splitlines())

    def verdict(cls, severity, action, reason):
        return {
            "class": cls,
            "severity": severity,
            "top_frame": top or "no-frames",
            "action": action,
            "reason": reason,
        }

    # --- AddressSanitizer hard memory errors (highest confidence) -------------
    if "addresssanitizer" in low or "error: addresssanitizer" in low:
        for bug in _ASAN_MEMORY_BUGS:
            if bug in low:
                is_write = bool(re.search(r"\bwrite of size", low))
                kind = "write" if is_write else "read"
                return verdict(
                    "memory-bug",
                    "HIGH",
                    "file-upstream",
                    f"ASAN {bug} ({kind}). Memory-safety bug; the PoC is ready to "
                    "report. A write primitive is typically more severe than a read.",
                )
        if "segv on unknown address" in low or "deadly signal" in low:
            addr = _segv_address(text)
            if addr is not None and addr < 0x1000:
                return verdict(
                    "segv",
                    "MED",
                    "investigate",
                    f"ASAN caught SEGV near null (0x{addr:x}); likely a null/"
                    "small-offset deref. Real bug, but often lower impact than a "
                    "controlled overflow — confirm whether the pointer is attacker-influenced.",
                )
            return verdict(
                "segv",
                "HIGH",
                "file-upstream",
                "ASAN caught a SEGV at a non-null address — treat as a real "
                "memory-corruption bug.",
            )

    # --- LeakSanitizer ---------------------------------------------------------
    if "leaksanitizer" in low or "detected memory leaks" in low:
        return verdict(
            "leak",
            "LOW",
            "investigate",
            "Memory leak. Rarely a security issue on its own; relevant for "
            "long-running services or as a DoS vector. Confirm it's reachable repeatedly.",
        )

    # --- UndefinedBehaviorSanitizer -------------------------------------------
    if "undefinedbehaviorsanitizer" in low or "runtime error:" in low:
        detail = ""
        m = re.search(r"runtime error:\s*(.+)", text)
        if m:
            detail = m.group(1).strip()
        sev = "MED"
        if any(
            k in low
            for k in ("out of bounds", "null pointer", "misaligned", "not a valid")
        ):
            sev = "HIGH"
        return verdict(
            "ubsan",
            sev,
            "investigate",
            f"UBSan: {detail or 'undefined behavior'}. Real bug unless it lies on "
            "a known-benign path. OOB-index and bad-pointer UB rank higher than "
            "signed-overflow on an int counter.",
        )

    # --- Debugger-only signals (no sanitizer report) --------------------------
    if re.search(r"sigsegv|exc_bad_access", low):
        addr = _segv_address(text)
        if addr is not None and addr < 0x1000:
            return verdict(
                "segv",
                "MED",
                "investigate",
                "SIGSEGV near null. Likely a null deref — real bug, impact depends "
                "on whether the pointer/offset is attacker-controlled. Rebuild with "
                "ASAN for a precise diagnosis.",
            )
        return verdict(
            "segv",
            "HIGH",
            "file-upstream",
            "SIGSEGV at a non-null address with no sanitizer report. Likely memory "
            "corruption — rebuild with ASAN to confirm the access type.",
        )

    if re.search(r"sigabrt|__assert_fail|assertion.*failed|\babort\b", low):
        return verdict(
            "assertion",
            "LOW",
            "ignore-intended",
            "Assertion/abort. Usually working-as-intended: the parser rejected "
            "malformed input via its own check. Escalate only if the assertion "
            "guards a real invariant the input shouldn't be able to break.",
        )

    if re.search(r"sigtrap|exc_breakpoint|__builtin_trap|ud2|illegal instruction|sigill", low):
        return verdict(
            "trap",
            "MED",
            "investigate",
            "Trap/illegal-instruction. Often a compiler-inserted safety check "
            "(__builtin_trap from a checked-arithmetic or bounds guard) rather than "
            "raw corruption. Read the top-frame source to tell which.",
        )

    if re.search(r"sigfpe|floating point exception|division by zero", low):
        return verdict(
            "arith",
            "MED",
            "investigate",
            "Arithmetic fault (div-by-zero or INT_MIN/-1). Typically a DoS-class "
            "bug, not memory corruption.",
        )

    if re.search(r"sigbus|exc_bad_instruction", low):
        return verdict(
            "memory-bug",
            "MED",
            "investigate",
            "SIGBUS — misaligned or bad memory access. Rebuild with ASAN for a "
            "precise classification.",
        )

    if "timeout" in low or "hang" in low:
        return verdict(
            "hang",
            "LOW",
            "investigate",
            "Timeout/hang rather than a crash. Possible algorithmic-complexity or "
            "infinite-loop DoS; not a memory-safety bug.",
        )

    if top is None or top == "no-frames":
        return verdict(
            "no-frames",
            "UNKNOWN",
            "investigate",
            "No usable stack frames or signal in the trace. Re-capture with a "
            "symbolized ASAN build, or run under a debugger to get a backtrace.",
        )

    return verdict(
        "unknown",
        "UNKNOWN",
        "investigate",
        "Crash with a backtrace but no recognized sanitizer/signal marker. "
        "Inspect the top-frame source to classify manually.",
    )


def render(v, label=None):
    width = 11
    head = f"Hash:       {label}\n" if label else ""
    return (
        f"{head}"
        f"{'Class:':<{width}} {v['class']}\n"
        f"{'Severity:':<{width}} {v['severity']}\n"
        f"{'Top frame:':<{width}} {v['top_frame']}\n"
        f"{'Action:':<{width}} {v['action']}\n"
        f"{'Reasoning:':<{width}} {v['reason']}"
    )


def main():
    ap = argparse.ArgumentParser(description="Classify a crash trace.")
    ap.add_argument("trace", nargs="?", help="Trace file (default: stdin)")
    ap.add_argument("--label", help="Optional identifier (e.g. crash hash) for the header")
    ap.add_argument("--json", action="store_true", help="Emit JSON only")
    ap.add_argument("-o", "--output", help="Write JSON verdict to this file")
    args = ap.parse_args()

    if args.trace and args.trace != "-":
        with open(args.trace, "r", errors="replace") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()

    if not text.strip():
        print("error: empty trace", file=sys.stderr)
        return 2

    v = classify(text)
    if args.label:
        v = {"label": args.label, **v}

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(v, fh, indent=2)

    if args.json:
        print(json.dumps(v, indent=2))
    else:
        print(render(v, args.label))
    return 0


if __name__ == "__main__":
    sys.exit(main())
