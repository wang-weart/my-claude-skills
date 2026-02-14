#!/usr/bin/env python3
"""Build cross-reference maps: callers/callees and data references."""

import sys
import os
import json

import angr


def main():
    if len(sys.argv) < 2:
        print("Usage: export_xrefs.py <binary>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]
    name = os.path.basename(binary_path).split(".")[0]
    output_dir = os.environ.get("ANGR_OUTPUT_DIR", ".")
    auto_load = os.environ.get("ANGR_AUTO_LOAD_LIBS", "false").lower() == "true"
    output_path = os.path.join(output_dir, f"{name}_xrefs.json")

    kwargs = {"auto_load_libs": auto_load}
    base = os.environ.get("ANGR_BASE_ADDR", "")
    if base:
        kwargs["main_opts"] = {"base_addr": int(base, 0)}

    print(f"Loading {binary_path}...", file=sys.stderr)
    proj = angr.Project(binary_path, **kwargs)

    print(f"Running CFGFast with data references...", file=sys.stderr)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

    cg = cfg.kb.callgraph
    result = []

    for addr in sorted(cfg.kb.functions.keys()):
        func = cfg.kb.functions[addr]
        if func.is_simprocedure:
            continue

        # Code xrefs: callers
        callers = []
        if cg.has_node(addr):
            for caller_addr in cg.predecessors(addr):
                if caller_addr in cfg.kb.functions:
                    callers.append({
                        "name": cfg.kb.functions[caller_addr].name,
                        "address": hex(caller_addr),
                    })
                if len(callers) >= 50:
                    break

        # Code xrefs: callees
        callees = []
        if cg.has_node(addr):
            for callee_addr in cg.successors(addr):
                if callee_addr in cfg.kb.functions:
                    callees.append({
                        "name": cfg.kb.functions[callee_addr].name,
                        "address": hex(callee_addr),
                    })
                if len(callees) >= 50:
                    break

        # Data references (string/constant refs from this function)
        data_refs = []
        try:
            xrefs = proj.kb.xrefs
            if hasattr(xrefs, "get_xrefs_by_ins_addr"):
                for block in func.blocks:
                    for ins_addr in block.instruction_addrs:
                        refs = xrefs.get_xrefs_by_ins_addr(ins_addr)
                        for ref in refs:
                            if hasattr(ref, "dst"):
                                data_refs.append({
                                    "from_instruction": hex(ins_addr),
                                    "to_address": hex(ref.dst),
                                    "type": ref.type_string if hasattr(ref, "type_string") else "unknown",
                                })
                            if len(data_refs) >= 100:
                                break
                        if len(data_refs) >= 100:
                            break
        except Exception:
            pass

        entry = {
            "name": func.name,
            "address": hex(func.addr),
            "callers": callers,
            "callees": callees,
            "caller_count": len(callers),
            "callee_count": len(callees),
        }
        if data_refs:
            entry["data_refs"] = data_refs

        result.append(entry)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Exported xrefs for {len(result)} functions to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
