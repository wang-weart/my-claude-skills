# my-claude-skills

Security analysis skills for Claude Code: static binary analysis (angr), dynamic binary instrumentation (Frida), network capture analysis (pcap), and crash triage.

## Install

Install all plugins at once:

```bash
claude plugin add --from-marketplace sandbornm/my-claude-skills
```

Or install individual plugins:

```bash
# Static binary analysis (angr)
claude plugin add sandbornm/my-claude-skills/angr-analyzer

# Dynamic binary instrumentation (Frida)
claude plugin add sandbornm/my-claude-skills/frida-instrument

# Network capture analysis (pcap)
claude plugin add sandbornm/my-claude-skills/pcap-analyzer

# Crash triage and classification
claude plugin add sandbornm/my-claude-skills/crash-triage
```

## Plugins

### angr-analyzer

Static binary analysis using angr's Python framework. Decompile executables, recover control flow graphs, find vulnerabilities via symbolic execution, and extract symbols from stripped binaries.

**Prerequisites:** Python 3.8+, `pip install angr`

### frida-instrument

Dynamic binary instrumentation using Frida. Trace function calls at runtime, hook APIs, inspect process memory, enumerate loaded modules, and perform instruction-level tracing on live processes.

**Prerequisites:** Python 3, `pip install frida-tools`

### pcap-analyzer

Network capture analysis for digital forensics and reverse engineering. Extract TCP/UDP streams, DNS queries, HTTP transactions, cleartext credentials, and transferred files. Detect C2 beaconing, port scanning, data exfiltration, and DNS tunneling.

**Prerequisites:** Python 3.8+, `pip install scapy` (optional: install tshark via Wireshark for enhanced features)

### crash-triage

Triage and classify program crashes by bug class and exploitability. Reproduce a crashing input under ASAN/UBSan or a debugger, classify ASAN reports and GDB/LLDB backtraces (memory-bug, segv, ubsan, assertion, trap, leak, …), and emit a severity-ranked verdict with the responsible source frame and a recommended action. Useful for reviewing fuzzer-found crashes and deciding what to report upstream.

**Prerequisites:** Python 3 (stdlib only). For reproduction: the target binary (ideally an ASAN+UBSan build); optionally `gdb` or `lldb` for a backtrace fallback.
