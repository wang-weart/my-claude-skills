---
name: frida-instrument
description: >-
  Instruments running binaries using Frida's dynamic analysis toolkit. Use when
  tracing function calls at runtime, hooking APIs, inspecting process memory,
  enumerating loaded modules, or performing instruction-level tracing on live
  processes.
---

# Frida Dynamic Instrumentation

Perform dynamic binary analysis using Frida's instrumentation toolkit. Attach
to or spawn processes, hook functions, trace calls, inspect memory, and perform
instruction-level tracing at runtime.

## When to Use

- Tracing function calls and arguments at runtime
- Hooking and modifying API behavior in a running process
- Enumerating loaded modules, exports, and imports at runtime
- Inspecting or scanning process memory for patterns
- Instruction-level code tracing (Stalker)
- Analyzing malware behavior in a sandbox
- Runtime reverse engineering when static analysis is insufficient
- API monitoring and protocol reverse engineering

## When NOT to Use

- Binary is not executable on the current platform — use static tools (Ghidra, angr)
- Pure static analysis is sufficient — use Ghidra or angr
- Need full decompilation — use Ghidra
- Need symbolic execution — use angr
- Process requires kernel-level instrumentation — use DTrace, eBPF
- Target is a .NET or Java application — use dnSpy/jadx

## Quick Reference

| Task | Command |
|------|---------|
| Full enumeration (spawn) | `{baseDir}/scripts/frida-analyze.sh --spawn ./binary -s enumerate_all.js -o ./output` |
| Full enumeration (attach) | `{baseDir}/scripts/frida-analyze.sh --attach <pid> -s enumerate_all.js -o ./output` |
| List modules | `{baseDir}/scripts/frida-analyze.sh --attach <pid> -s enumerate_modules.js -o ./output` |
| List exports | `{baseDir}/scripts/frida-analyze.sh --attach <pid> -s enumerate_exports.js -o ./output` |
| List imports | `{baseDir}/scripts/frida-analyze.sh --attach <pid> -s enumerate_imports.js -o ./output` |
| Trace function calls | `{baseDir}/scripts/frida-analyze.sh --spawn ./binary -s trace_calls.js -a '{"functions":["open","read","write"]}' -o ./output` |
| Hook functions | `{baseDir}/scripts/frida-analyze.sh --attach <pid> -s hook_functions.js -a '{"functions":["malloc","free"]}' -o ./output` |
| Dump memory | `{baseDir}/scripts/frida-analyze.sh --attach <pid> -s dump_memory.js -a '{"module":"libc.so"}' -o ./output` |
| Scan memory | `{baseDir}/scripts/frida-analyze.sh --attach <pid> -s scan_memory.js -a '{"pattern":"50 41 53 53"}' -o ./output` |
| Stalker trace | `{baseDir}/scripts/frida-analyze.sh --spawn ./binary -s stalker_trace.js -a '{"function":"main"}' -o ./output` |

## Prerequisites

- **Python 3** with pip
- **frida-tools**: `pip install frida-tools`
- On macOS/Linux: may need to run as root for attaching to processes
- On iOS/Android: Frida server must be running on the device

## Main Wrapper Script

```bash
{baseDir}/scripts/frida-analyze.sh [options]
```

**Options:**
- `--spawn <binary>` — Launch binary and instrument it
- `--attach <pid_or_name>` — Attach to a running process
- `-o, --output <dir>` — Output directory (default: current dir)
- `-s, --script <name>` — Agent script to run (can be repeated)
- `-a, --script-args <json>` — JSON arguments for the last specified script
- `-D, --device <id>` — Device ID (for USB/remote devices)
- `-U, --usb` — Use USB-connected device
- `--no-pause` — Don't pause spawned process (auto-resume)
- `--timeout <seconds>` — Script timeout
- `-v, --verbose` — Verbose output

## Built-in Agent Scripts

### enumerate_all.js

Comprehensive runtime enumeration: process info, modules, main module
exports/imports, and memory layout.

**Output:** `{name}_enumeration.json`

### enumerate_modules.js

List all loaded modules with base addresses, sizes, and file paths.

**Output:** `{name}_modules.json`

### enumerate_exports.js

List function and variable exports. Pass `{"module":"libname"}` to target a
specific module, or enumerates main module by default.

**Output:** `{name}_exports.json`

### enumerate_imports.js

List imports. Pass `{"module":"libname"}` to target a specific module.

**Output:** `{name}_imports.json`

### trace_calls.js

Trace function calls with arguments and return values using Interceptor.
Pass `{"functions":["open","read","write"]}` to specify which functions to
trace.

**Output:** Real-time trace to console + `{name}_trace.json`

### hook_functions.js

Hook functions to log or modify behavior. Pass function names and optional
actions (log, replace return value, skip).

**Output:** `{name}_hooks.json`

### dump_memory.js

Dump memory regions. Pass `{"module":"libname"}` to dump a module, or
`{"address":"0x...","size":4096}` for a specific region.

**Output:** `{name}_memdump.txt` (hex) and `{name}_memdump.bin` (raw)

### scan_memory.js

Scan process memory for byte patterns or strings. Pass
`{"pattern":"48 89 5c 24 ??"}` for hex patterns with wildcards, or
`{"string":"password"}` for string search.

**Output:** `{name}_scan_results.json`

### stalker_trace.js

Instruction-level code tracing using Frida's Stalker engine. Pass
`{"function":"main"}` or `{"address":"0x..."}` to trace from a specific
entry point. Records basic blocks, calls, and returns.

**Output:** `{name}_stalker.json`

## Common Workflows

### Trace System Calls of a Program

```bash
{baseDir}/scripts/frida-analyze.sh \
    --spawn ./target_program \
    -s trace_calls.js \
    -a '{"functions":["open","read","write","connect","send","recv"]}' \
    -o ./traces
```

### Enumerate Everything from a Running Process

```bash
{baseDir}/scripts/frida-analyze.sh \
    --attach myapp \
    -s enumerate_all.js \
    -o ./output
cat ./output/myapp_enumeration.json | jq '.modules[:5]'
```

### Search for Secrets in Memory

```bash
{baseDir}/scripts/frida-analyze.sh \
    --attach myapp \
    -s scan_memory.js \
    -a '{"string":"password"}' \
    -o ./scan
cat ./scan/myapp_scan_results.json
```

### Hook malloc/free for Heap Analysis

```bash
{baseDir}/scripts/frida-analyze.sh \
    --spawn ./target \
    -s hook_functions.js \
    -a '{"functions":["malloc","free"]}' \
    -o ./heap
```

### Instruction-Level Trace of a Function

```bash
{baseDir}/scripts/frida-analyze.sh \
    --spawn ./target \
    -s stalker_trace.js \
    -a '{"function":"main"}' \
    --timeout 30 \
    -o ./trace
```

## Platform Notes

- **macOS**: System Integrity Protection may block instrumentation of system processes. Use `csrutil disable` in recovery mode or target user processes.
- **Linux**: May need `sudo` or `ptrace_scope=0` (`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`)
- **iOS**: Requires jailbreak and frida-server running on device. Use `-U` flag.
- **Android**: Requires rooted device or frida-gadget. Use `-U` flag.

## Troubleshooting

### Frida Not Installed

```bash
pip install frida-tools
```

### Permission Denied

```bash
# Linux
sudo {baseDir}/scripts/frida-analyze.sh --attach <pid> ...

# Or adjust ptrace scope
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### Process Crashes on Attach

Some anti-debug protections prevent attachment. Try spawning instead:
```bash
{baseDir}/scripts/frida-analyze.sh --spawn ./binary -s enumerate_all.js
```

### Script Timeout

```bash
{baseDir}/scripts/frida-analyze.sh --timeout 60 --spawn ./binary -s trace_calls.js -a '{"functions":["main"]}'
```

## Tips

1. **Spawn vs Attach** — Use `--spawn` to catch early initialization; `--attach` for long-running processes
2. **Start with enumerate_all.js** — gives a complete picture of the running process
3. **Stalker is heavyweight** — only trace specific functions, not the entire process
4. **Frida + angr complement each other** — use angr for static CFG, then Frida to validate runtime paths
5. **JSON args** — all script arguments are passed as JSON strings via `-a`
6. **Use jq** — output is JSON, pipe through jq for filtering
