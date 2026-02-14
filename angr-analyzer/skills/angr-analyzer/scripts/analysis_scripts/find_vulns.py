#!/usr/bin/env python3
"""Detect dangerous function patterns and potential vulnerabilities."""

import sys
import os
import json

import angr


DANGEROUS_FUNCTIONS = {
    "strcpy": "Buffer overflow: unbounded string copy",
    "strncpy": "Potential off-by-one or missing null terminator",
    "strcat": "Buffer overflow: unbounded string concatenation",
    "strncat": "Potential off-by-one",
    "sprintf": "Buffer overflow: unbounded formatted output",
    "vsprintf": "Buffer overflow: unbounded formatted output",
    "gets": "Buffer overflow: never use gets()",
    "scanf": "Buffer overflow: unbounded input without width specifier",
    "sscanf": "Buffer overflow: unbounded input without width specifier",
    "system": "Command injection: executes shell command",
    "popen": "Command injection: executes shell command",
    "exec": "Arbitrary code execution",
    "execve": "Arbitrary code execution",
    "execvp": "Arbitrary code execution",
    "dlopen": "Dynamic library loading — code injection vector",
    "mprotect": "Memory protection change — potential RWX",
    "mmap": "Memory mapping — check for RWX permissions",
    "memcpy": "Buffer overflow if size unchecked",
    "memmove": "Buffer overflow if size unchecked",
    "alloca": "Stack overflow: dynamic stack allocation",
    "setuid": "Privilege management",
    "setgid": "Privilege management",
    "chmod": "File permission change",
    "chown": "File ownership change",
}

SENSITIVE_STRINGS = [
    "password", "passwd", "secret", "private_key", "api_key",
    "token", "credential", "authorization", "bearer",
    "admin", "root", "sudo",
    "/etc/shadow", "/etc/passwd",
    "BEGIN RSA", "BEGIN PRIVATE",
]


def main():
    if len(sys.argv) < 2:
        print("Usage: find_vulns.py <binary>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]
    name = os.path.basename(binary_path).split(".")[0]
    output_dir = os.environ.get("ANGR_OUTPUT_DIR", ".")
    auto_load = os.environ.get("ANGR_AUTO_LOAD_LIBS", "false").lower() == "true"
    output_path = os.path.join(output_dir, f"{name}_vulns.json")

    kwargs = {"auto_load_libs": auto_load}
    base = os.environ.get("ANGR_BASE_ADDR", "")
    if base:
        kwargs["main_opts"] = {"base_addr": int(base, 0)}

    print(f"Loading {binary_path}...", file=sys.stderr)
    proj = angr.Project(binary_path, **kwargs)

    print(f"Running CFGFast...", file=sys.stderr)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

    cg = cfg.kb.callgraph
    result = {
        "binary": os.path.basename(binary_path),
        "architecture": proj.arch.name,
        "dangerous_calls": [],
        "sensitive_strings": [],
        "potential_vulns": [],
    }

    # Find calls to dangerous functions
    print(f"  Checking for dangerous function calls...", file=sys.stderr)
    for addr, func in cfg.kb.functions.items():
        func_lower = func.name.lower()
        for dangerous_name, risk in DANGEROUS_FUNCTIONS.items():
            if func_lower == dangerous_name or func_lower.endswith(f"_{dangerous_name}"):
                # Find callers of this dangerous function
                callers = []
                if cg.has_node(addr):
                    for caller_addr in cg.predecessors(addr):
                        if caller_addr in cfg.kb.functions:
                            callers.append({
                                "name": cfg.kb.functions[caller_addr].name,
                                "address": hex(caller_addr),
                            })

                result["dangerous_calls"].append({
                    "function": func.name,
                    "address": hex(addr),
                    "risk": risk,
                    "called_by": callers,
                    "caller_count": len(callers),
                })

    # Scan for sensitive strings
    print(f"  Scanning for sensitive strings...", file=sys.stderr)
    obj = proj.loader.main_object
    if hasattr(obj, "sections") and obj.sections:
        for sec in obj.sections:
            if sec.memsize == 0 or sec.memsize > 10 * 1024 * 1024:
                continue
            try:
                data = proj.loader.memory.load(sec.vaddr, sec.memsize)
                text = data.decode("ascii", errors="ignore").lower()
                for pattern in SENSITIVE_STRINGS:
                    idx = 0
                    while True:
                        idx = text.find(pattern.lower(), idx)
                        if idx == -1:
                            break
                        # Extract context around the match
                        start = max(0, idx - 20)
                        end = min(len(text), idx + len(pattern) + 20)
                        context = text[start:end].replace("\x00", "").strip()
                        result["sensitive_strings"].append({
                            "pattern": pattern,
                            "address": hex(sec.vaddr + idx),
                            "section": sec.name,
                            "context": context,
                        })
                        idx += len(pattern)
            except Exception:
                continue

    # Summarize potential vulnerabilities
    if result["dangerous_calls"]:
        for dc in result["dangerous_calls"]:
            if dc["function"] in ("gets", "strcpy", "sprintf", "strcat"):
                result["potential_vulns"].append({
                    "type": "buffer_overflow",
                    "severity": "high",
                    "function": dc["function"],
                    "address": dc["address"],
                    "description": dc["risk"],
                    "called_by": [c["name"] for c in dc["called_by"]],
                })
            elif dc["function"] in ("system", "popen", "exec", "execve"):
                result["potential_vulns"].append({
                    "type": "command_injection",
                    "severity": "critical",
                    "function": dc["function"],
                    "address": dc["address"],
                    "description": dc["risk"],
                    "called_by": [c["name"] for c in dc["called_by"]],
                })

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nResults:", file=sys.stderr)
    print(f"  Dangerous function calls: {len(result['dangerous_calls'])}", file=sys.stderr)
    print(f"  Sensitive strings: {len(result['sensitive_strings'])}", file=sys.stderr)
    print(f"  Potential vulnerabilities: {len(result['potential_vulns'])}", file=sys.stderr)
    print(f"Output: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
