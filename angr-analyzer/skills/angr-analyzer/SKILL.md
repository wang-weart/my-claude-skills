---
name: angr-analyzer
description: >-
  Analyzes binaries using angr's Python framework for static analysis, symbolic
  execution, and vulnerability detection. Use when decompiling executables,
  recovering control flow graphs, finding vulnerabilities via symbolic execution,
  or analyzing stripped binaries without source access.
---

# angr Binary Analysis

Perform automated binary analysis using angr's Python framework. Load binaries,
recover control flow, decompile to C, extract symbols, and run symbolic
execution to find bugs and solve for inputs.

## When to Use

- Decompiling a binary to C pseudocode (works on stripped binaries)
- Recovering control flow graphs from executables
- Finding vulnerabilities via symbolic execution and taint analysis
- Extracting functions, strings, and symbols from binaries
- Solving for inputs that reach specific code paths (CTF, crash analysis)
- Cross-referencing functions and data in compiled code
- Analyzing firmware or embedded binaries

## When NOT to Use

- Source code is available — read it directly
- Interactive debugging needed — use GDB, LLDB
- Dynamic runtime analysis needed — use Frida or a debugger
- .NET assembly — use dnSpy or ILSpy
- Java bytecode — use jadx or cfr
- Quick string/symbol dump only — `strings` or `nm` may suffice

## Quick Reference

| Task | Command |
|------|---------|
| Full analysis | `{baseDir}/scripts/angr-analyze.sh -s analyze_all.py -o ./output binary` |
| Decompile to C | `{baseDir}/scripts/angr-analyze.sh -s decompile.py -o ./output binary` |
| List functions | `{baseDir}/scripts/angr-analyze.sh -s export_functions.py -o ./output binary` |
| Extract strings | `{baseDir}/scripts/angr-analyze.sh -s export_strings.py -o ./output binary` |
| Control flow graph | `{baseDir}/scripts/angr-analyze.sh -s export_cfg.py -o ./output binary` |
| Export symbols | `{baseDir}/scripts/angr-analyze.sh -s export_symbols.py -o ./output binary` |
| Cross-references | `{baseDir}/scripts/angr-analyze.sh -s export_xrefs.py -o ./output binary` |
| Find vulnerabilities | `{baseDir}/scripts/angr-analyze.sh -s find_vulns.py -o ./output binary` |
| Symbolic execution | `{baseDir}/scripts/angr-analyze.sh -s symbolic_explore.py -a "--find 0x401234 --avoid 0x401300" -o ./output binary` |

## Prerequisites

- **Python 3.8+** with pip
- **angr**: `pip install angr`

## Main Wrapper Script

```bash
{baseDir}/scripts/angr-analyze.sh [options] <binary>
```

**Options:**
- `-o, --output <dir>` — Output directory for results (default: current dir)
- `-s, --script <name>` — Analysis script to run (can be repeated)
- `-a, --script-args <args>` — Arguments for the last specified script
- `--base-addr <addr>` — Base address for position-independent binaries
- `--auto-load-libs` — Load shared library dependencies (default: off)
- `--timeout <seconds>` — Analysis timeout
- `-v, --verbose` — Verbose output
- `-h, --help` — Show help

## Built-in Analysis Scripts

### analyze_all.py

Runs summary, decompilation, function listing, string extraction, and
interesting-pattern detection. Best for initial triage.

**Output files:**
- `{name}_summary.txt` — Architecture, entry point, sections, function counts
- `{name}_decompiled.c` — All functions decompiled to C
- `{name}_functions.json` — Function list with metadata
- `{name}_strings.json` — Extracted strings with addresses
- `{name}_interesting.txt` — Security-relevant function patterns

### decompile.py

Decompile all recovered functions to C pseudocode using angr's decompiler.

**Output:** `{name}_decompiled.c`

### export_functions.py

Export recovered functions as JSON with addresses, sizes, calling convention,
and call targets.

**Output:** `{name}_functions.json`

### export_strings.py

Extract ASCII and Unicode strings from binary sections.

**Output:** `{name}_strings.json`

### export_cfg.py

Recover and export the control flow graph — angr's core strength. Includes
nodes (functions/blocks), edges (calls/jumps), entry points, and call
frequency analysis.

**Output:** `{name}_cfg.json`

### export_symbols.py

Export all symbols, imports, exports, sections, and segments.

**Output:** `{name}_symbols.json`

### export_xrefs.py

Build cross-reference maps: callers/callees for each function, plus data
references.

**Output:** `{name}_xrefs.json`

### find_vulns.py

Pattern-based vulnerability detection: dangerous function calls (strcpy,
sprintf, gets, system), format string issues, and sensitive string references.

**Output:** `{name}_vulns.json`

### symbolic_explore.py

Symbolic execution — angr's unique capability. Find inputs that reach a
target address while avoiding others.

**Arguments:** `--find <addr> --avoid <addr> [--avoid <addr>...] --timeout <secs>`

**Output:** `{name}_symbolic.json` with found states, stdin, stdout, and
constraint details.

## Common Workflows

### Triage an Unknown Binary

```bash
mkdir -p ./analysis
{baseDir}/scripts/angr-analyze.sh -s analyze_all.py -o ./analysis unknown_bin
cat ./analysis/unknown_bin_summary.txt
cat ./analysis/unknown_bin_interesting.txt
```

### Find a Path to a Target Function (CTF)

```bash
# First find the target address
{baseDir}/scripts/angr-analyze.sh -s export_functions.py -o ./out binary
cat ./out/binary_functions.json | jq '.[] | select(.name=="win")'

# Then solve for input
{baseDir}/scripts/angr-analyze.sh \
    -s symbolic_explore.py \
    -a "--find 0x401234 --avoid 0x401300" \
    -o ./out binary
cat ./out/binary_symbolic.json
```

### Analyze Firmware

```bash
{baseDir}/scripts/angr-analyze.sh \
    --base-addr 0x08000000 \
    -s analyze_all.py \
    -o ./fw_analysis \
    firmware.bin
```

### Security Audit

```bash
{baseDir}/scripts/angr-analyze.sh -s find_vulns.py -o ./audit target_binary
{baseDir}/scripts/angr-analyze.sh -s export_xrefs.py -o ./audit target_binary
cat ./audit/target_binary_vulns.json | jq '.dangerous_calls'
```

## Troubleshooting

### angr Not Installed

```bash
pip install angr
# Or in a virtualenv:
python3 -m venv angr-env && source angr-env/bin/activate && pip install angr
```

### Analysis Takes Too Long

```bash
{baseDir}/scripts/angr-analyze.sh --timeout 300 -s analyze_all.py binary
```

### Out of Memory on Large Binaries

angr can be memory-intensive. For large binaries:
- Use individual scripts instead of analyze_all.py
- Avoid CFGEmulated (CFGFast is used by default and is much lighter)
- Increase system swap or use a machine with more RAM

### Wrong Architecture

angr auto-detects architecture from ELF/PE headers. For raw firmware, specify
the base address with `--base-addr`.

## Tips

1. **Start with analyze_all.py** — gives a full overview for triage
2. **CFGFast vs CFGEmulated** — scripts use CFGFast (fast, incomplete) by default; CFGEmulated is more accurate but much slower
3. **Stripped binaries work** — angr recovers functions even without symbols
4. **Symbolic execution needs targets** — always specify --find address for symbolic_explore.py
5. **Use jq for JSON** — all JSON exports are designed for machine processing
6. **angr's decompiler is experimental** — cross-reference with Ghidra for critical analysis
