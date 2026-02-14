#!/usr/bin/env python3
"""Export all symbols, imports, exports, sections, and segments."""

import sys
import os
import json

import angr


def main():
    if len(sys.argv) < 2:
        print("Usage: export_symbols.py <binary>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]
    name = os.path.basename(binary_path).split(".")[0]
    output_dir = os.environ.get("ANGR_OUTPUT_DIR", ".")
    auto_load = os.environ.get("ANGR_AUTO_LOAD_LIBS", "false").lower() == "true"
    output_path = os.path.join(output_dir, f"{name}_symbols.json")

    kwargs = {"auto_load_libs": auto_load}
    base = os.environ.get("ANGR_BASE_ADDR", "")
    if base:
        kwargs["main_opts"] = {"base_addr": int(base, 0)}

    print(f"Loading {binary_path}...", file=sys.stderr)
    proj = angr.Project(binary_path, **kwargs)

    obj = proj.loader.main_object
    result = {"binary": os.path.basename(binary_path)}

    # Symbols
    symbols = []
    if hasattr(obj, "symbols"):
        for sym in obj.symbols:
            if sym.name and not sym.name.startswith("__"):
                entry = {
                    "name": sym.name,
                    "address": hex(sym.rebased_addr) if sym.rebased_addr else None,
                    "size": sym.size,
                    "type": sym.type.name if hasattr(sym.type, "name") else str(sym.type),
                    "is_function": sym.is_function,
                    "is_import": sym.is_import,
                    "is_export": sym.is_export,
                }
                symbols.append(entry)
                if len(symbols) >= 10000:
                    break

    result["symbols"] = symbols
    result["symbol_count"] = len(symbols)

    # Imports (PLT entries on ELF)
    imports = []
    if hasattr(obj, "imports"):
        for imp_name, imp_sym in obj.imports.items():
            imports.append({
                "name": imp_name,
                "address": hex(imp_sym.rebased_addr) if imp_sym.rebased_addr else None,
            })
    elif hasattr(obj, "plt"):
        for name, addr in obj.plt.items():
            imports.append({"name": name, "address": hex(addr)})

    result["imports"] = imports

    # Exports
    exports = []
    for sym in symbols:
        if sym["is_export"]:
            exports.append({"name": sym["name"], "address": sym["address"]})
    result["exports"] = exports

    # Sections
    sections = []
    if hasattr(obj, "sections") and obj.sections:
        for sec in obj.sections:
            sections.append({
                "name": sec.name,
                "address": hex(sec.vaddr),
                "size": sec.memsize,
                "file_offset": sec.offset if hasattr(sec, "offset") else None,
                "executable": sec.is_executable if hasattr(sec, "is_executable") else None,
                "writable": sec.is_writable if hasattr(sec, "is_writable") else None,
                "readable": sec.is_readable if hasattr(sec, "is_readable") else None,
            })
    result["sections"] = sections

    # Segments
    segments = []
    if hasattr(obj, "segments") and obj.segments:
        for seg in obj.segments:
            segments.append({
                "address": hex(seg.vaddr),
                "size": seg.memsize,
                "file_size": seg.filesize,
                "offset": seg.offset,
            })
    result["segments"] = segments

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Exported {len(symbols)} symbols, {len(imports)} imports, "
          f"{len(exports)} exports to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
