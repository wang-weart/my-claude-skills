#!/usr/bin/env python3
"""Export recovered functions as JSON with addresses, sizes, and call targets."""

import sys
import os
import json

import angr


def main():
    if len(sys.argv) < 2:
        print("Usage: export_functions.py <binary>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]
    name = os.path.basename(binary_path).split(".")[0]
    output_dir = os.environ.get("ANGR_OUTPUT_DIR", ".")
    auto_load = os.environ.get("ANGR_AUTO_LOAD_LIBS", "false").lower() == "true"
    output_path = os.path.join(output_dir, f"{name}_functions.json")

    kwargs = {"auto_load_libs": auto_load}
    base = os.environ.get("ANGR_BASE_ADDR", "")
    if base:
        kwargs["main_opts"] = {"base_addr": int(base, 0)}

    print(f"Loading {binary_path}...", file=sys.stderr)
    proj = angr.Project(binary_path, **kwargs)

    print(f"Running CFGFast...", file=sys.stderr)
    cfg = proj.analyses.CFGFast(normalize=True)

    cg = cfg.kb.callgraph
    result = []

    for addr in sorted(cfg.kb.functions.keys()):
        func = cfg.kb.functions[addr]

        # Get callees
        callees = []
        if cg.has_node(addr):
            for target in cg.successors(addr):
                if target in cfg.kb.functions:
                    t = cfg.kb.functions[target]
                    callees.append({"name": t.name, "address": hex(target)})
                if len(callees) >= 50:
                    break

        # Get callers
        callers = []
        if cg.has_node(addr):
            for caller in cg.predecessors(addr):
                if caller in cfg.kb.functions:
                    c = cfg.kb.functions[caller]
                    callers.append({"name": c.name, "address": hex(caller)})
                if len(callers) >= 50:
                    break

        blocks = list(func.blocks)
        entry = {
            "name": func.name,
            "address": hex(func.addr),
            "size": func.size,
            "block_count": len(blocks),
            "is_plt": func.is_plt,
            "is_simprocedure": func.is_simprocedure,
            "has_return": func.has_return,
            "callees": callees,
            "callers": callers,
        }

        # Try to get calling convention info
        if func.calling_convention:
            entry["calling_convention"] = str(func.calling_convention)

        result.append(entry)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Exported {len(result)} functions to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
