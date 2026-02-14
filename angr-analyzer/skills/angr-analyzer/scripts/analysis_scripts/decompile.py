#!/usr/bin/env python3
"""Decompile all recovered functions to C pseudocode using angr's decompiler."""

import sys
import os

import angr


def main():
    if len(sys.argv) < 2:
        print("Usage: decompile.py <binary>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]
    name = os.path.basename(binary_path).split(".")[0]
    output_dir = os.environ.get("ANGR_OUTPUT_DIR", ".")
    auto_load = os.environ.get("ANGR_AUTO_LOAD_LIBS", "false").lower() == "true"
    output_path = os.path.join(output_dir, f"{name}_decompiled.c")

    print(f"Loading {binary_path}...", file=sys.stderr)
    kwargs = {"auto_load_libs": auto_load}
    base = os.environ.get("ANGR_BASE_ADDR", "")
    if base:
        kwargs["main_opts"] = {"base_addr": int(base, 0)}
    proj = angr.Project(binary_path, **kwargs)

    print(f"Running CFGFast...", file=sys.stderr)
    cfg = proj.analyses.CFGFast(normalize=True)
    print(f"Recovered {len(cfg.kb.functions)} functions", file=sys.stderr)

    count = 0
    failed = 0

    with open(output_path, "w") as f:
        f.write(f"/* Decompiled from: {os.path.basename(binary_path)} */\n")
        f.write(f"/* Architecture: {proj.arch.name} ({proj.arch.bits}-bit) */\n")
        f.write(f"/* Decompiler: angr */\n\n")

        for addr in sorted(cfg.kb.functions.keys()):
            func = cfg.kb.functions[addr]
            if func.is_plt or func.is_simprocedure:
                continue
            if func.size == 0:
                continue

            try:
                dec = proj.analyses.Decompiler(func, cfg=cfg.model)
                if dec.codegen and dec.codegen.text:
                    f.write(f"/* {func.name} @ {hex(func.addr)} (size: {func.size}) */\n")
                    f.write(dec.codegen.text)
                    f.write("\n\n")
                    count += 1
                else:
                    f.write(f"/* {func.name} @ {hex(func.addr)} — decompilation produced no output */\n\n")
                    failed += 1
            except Exception as e:
                f.write(f"/* {func.name} @ {hex(func.addr)} — decompilation failed: {e} */\n\n")
                failed += 1

    print(f"Decompiled {count} functions ({failed} failed)", file=sys.stderr)
    print(f"Output: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
