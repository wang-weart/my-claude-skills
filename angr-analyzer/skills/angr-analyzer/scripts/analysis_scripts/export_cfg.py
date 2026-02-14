#!/usr/bin/env python3
"""Recover and export the control flow graph as JSON."""

import sys
import os
import json

import angr


def main():
    if len(sys.argv) < 2:
        print("Usage: export_cfg.py <binary>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]
    name = os.path.basename(binary_path).split(".")[0]
    output_dir = os.environ.get("ANGR_OUTPUT_DIR", ".")
    auto_load = os.environ.get("ANGR_AUTO_LOAD_LIBS", "false").lower() == "true"
    output_path = os.path.join(output_dir, f"{name}_cfg.json")

    kwargs = {"auto_load_libs": auto_load}
    base = os.environ.get("ANGR_BASE_ADDR", "")
    if base:
        kwargs["main_opts"] = {"base_addr": int(base, 0)}

    print(f"Loading {binary_path}...", file=sys.stderr)
    proj = angr.Project(binary_path, **kwargs)

    print(f"Running CFGFast...", file=sys.stderr)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)

    cg = cfg.kb.callgraph

    # Build nodes
    nodes = []
    for addr in sorted(cfg.kb.functions.keys()):
        func = cfg.kb.functions[addr]
        nodes.append({
            "address": hex(func.addr),
            "name": func.name,
            "size": func.size,
            "block_count": len(list(func.blocks)),
            "is_plt": func.is_plt,
            "is_simprocedure": func.is_simprocedure,
        })

    # Build edges from call graph
    edges = []
    for src, dst in cg.edges():
        src_name = cfg.kb.functions[src].name if src in cfg.kb.functions else hex(src)
        dst_name = cfg.kb.functions[dst].name if dst in cfg.kb.functions else hex(dst)
        edges.append({
            "from_addr": hex(src),
            "from_name": src_name,
            "to_addr": hex(dst),
            "to_name": dst_name,
        })

    # Find entry points (no callers in call graph)
    entry_points = []
    for addr in cfg.kb.functions:
        if not list(cg.predecessors(addr)):
            func = cfg.kb.functions[addr]
            if not func.is_plt and not func.is_simprocedure:
                entry_points.append({
                    "name": func.name,
                    "address": hex(func.addr),
                })

    # Most-called functions
    call_counts = {}
    for _, dst in cg.edges():
        if dst in cfg.kb.functions:
            call_counts[dst] = call_counts.get(dst, 0) + 1

    most_called = sorted(call_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    most_called_list = [
        {"name": cfg.kb.functions[addr].name, "address": hex(addr), "call_count": count}
        for addr, count in most_called
        if addr in cfg.kb.functions
    ]

    result = {
        "total_functions": len(nodes),
        "total_edges": len(edges),
        "entry_points": entry_points,
        "most_called": most_called_list,
        "nodes": nodes,
        "edges": edges,
    }

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Exported CFG: {len(nodes)} nodes, {len(edges)} edges to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
