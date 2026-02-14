#!/usr/bin/env python3
"""Comprehensive angr analysis: summary, decompilation, functions, strings, patterns."""

import sys
import os
import json

import angr
from angr.knowledge_plugins.functions import Function


def get_output_path(name, suffix):
    output_dir = os.environ.get("ANGR_OUTPUT_DIR", ".")
    return os.path.join(output_dir, f"{name}{suffix}")


def should_auto_load():
    return os.environ.get("ANGR_AUTO_LOAD_LIBS", "false").lower() == "true"


def get_base_addr():
    addr = os.environ.get("ANGR_BASE_ADDR", "")
    if addr:
        return int(addr, 0)
    return None


def load_project(binary_path):
    kwargs = {"auto_load_libs": should_auto_load()}
    base = get_base_addr()
    if base is not None:
        kwargs["main_opts"] = {"base_addr": base}
    return angr.Project(binary_path, **kwargs)


def export_summary(proj, cfg, name):
    path = get_output_path(name, "_summary.txt")
    print(f"  Exporting summary to {os.path.basename(path)}", file=sys.stderr)

    obj = proj.loader.main_object
    funcs = list(cfg.kb.functions.values())

    with open(path, "w") as f:
        f.write("Binary Analysis Summary (angr)\n")
        f.write("==============================\n\n")
        f.write(f"File: {os.path.basename(proj.filename)}\n")
        f.write(f"Architecture: {proj.arch.name}\n")
        f.write(f"Bits: {proj.arch.bits}\n")
        f.write(f"Endianness: {proj.arch.memory_endness}\n")
        f.write(f"Entry Point: {hex(proj.entry)}\n")
        f.write(f"OS: {proj.loader.main_object.os}\n")
        f.write(f"Binary Type: {type(obj).__name__}\n\n")

        plt_funcs = [fn for fn in funcs if fn.is_plt]
        simprocedures = [fn for fn in funcs if fn.is_simprocedure]
        user_funcs = [fn for fn in funcs if not fn.is_plt and not fn.is_simprocedure]

        f.write("Functions:\n")
        f.write(f"  Total recovered: {len(funcs)}\n")
        f.write(f"  PLT stubs: {len(plt_funcs)}\n")
        f.write(f"  SimProcedures: {len(simprocedures)}\n")
        f.write(f"  User-defined: {len(user_funcs)}\n\n")

        if hasattr(obj, "sections") and obj.sections:
            f.write("Sections:\n")
            for sec in obj.sections:
                flags = ""
                if hasattr(sec, "is_executable") and sec.is_executable:
                    flags += " [X]"
                if hasattr(sec, "is_writable") and sec.is_writable:
                    flags += " [W]"
                if hasattr(sec, "is_readable") and sec.is_readable:
                    flags += " [R]"
                f.write(f"  {sec.name}: {hex(sec.vaddr)} - {hex(sec.vaddr + sec.memsize)}"
                        f" ({sec.memsize} bytes){flags}\n")
            f.write("\n")

        if hasattr(obj, "segments") and obj.segments:
            f.write("Segments:\n")
            for seg in obj.segments:
                f.write(f"  {hex(seg.vaddr)} - {hex(seg.vaddr + seg.memsize)}"
                        f" ({seg.memsize} bytes)\n")


def export_decompiled(proj, cfg, name):
    path = get_output_path(name, "_decompiled.c")
    print(f"  Exporting decompiled code to {os.path.basename(path)}", file=sys.stderr)

    count = 0
    failed = 0
    with open(path, "w") as f:
        f.write(f"/* Decompiled from: {os.path.basename(proj.filename)} (angr) */\n\n")

        for addr, func in sorted(cfg.kb.functions.items()):
            if func.is_plt or func.is_simprocedure:
                continue
            if func.size == 0:
                continue

            try:
                dec = proj.analyses.Decompiler(func, cfg=cfg.model)
                if dec.codegen and dec.codegen.text:
                    f.write(f"/* {func.name} @ {hex(func.addr)} */\n")
                    f.write(dec.codegen.text)
                    f.write("\n\n")
                    count += 1
                else:
                    failed += 1
            except Exception:
                failed += 1

    print(f"  Decompiled {count} functions ({failed} failed)", file=sys.stderr)


def export_functions(proj, cfg, name):
    path = get_output_path(name, "_functions.json")
    print(f"  Exporting functions to {os.path.basename(path)}", file=sys.stderr)

    result = []
    cg = cfg.kb.callgraph

    for addr, func in sorted(cfg.kb.functions.items()):
        callees = []
        if cg.has_node(addr):
            for target in cg.successors(addr):
                if target in cfg.kb.functions:
                    callees.append(cfg.kb.functions[target].name)
                if len(callees) >= 30:
                    break

        result.append({
            "name": func.name,
            "address": hex(func.addr),
            "size": func.size,
            "is_plt": func.is_plt,
            "is_simprocedure": func.is_simprocedure,
            "block_count": len(list(func.blocks)),
            "calls": callees,
        })

    with open(path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"  Exported {len(result)} functions", file=sys.stderr)


def export_strings(proj, name):
    path = get_output_path(name, "_strings.json")
    print(f"  Exporting strings to {os.path.basename(path)}", file=sys.stderr)

    obj = proj.loader.main_object
    strings = []

    # Scan sections for ASCII strings
    for sec in (obj.sections if hasattr(obj, "sections") and obj.sections else []):
        if sec.memsize == 0:
            continue
        try:
            data = proj.loader.memory.load(sec.vaddr, sec.memsize)
        except Exception:
            continue

        current = bytearray()
        start_addr = None

        for i, byte in enumerate(data):
            if 0x20 <= byte <= 0x7E:
                if not current:
                    start_addr = sec.vaddr + i
                current.append(byte)
            else:
                if len(current) >= 4:
                    try:
                        s = current.decode("ascii")
                        strings.append({
                            "address": hex(start_addr),
                            "value": s[:1000],
                            "length": len(s),
                            "section": sec.name,
                        })
                    except Exception:
                        pass
                current = bytearray()
                start_addr = None

        if len(current) >= 4:
            try:
                s = current.decode("ascii")
                strings.append({
                    "address": hex(start_addr),
                    "value": s[:1000],
                    "length": len(s),
                    "section": sec.name,
                })
            except Exception:
                pass

    with open(path, "w") as f:
        json.dump(strings, f, indent=2)

    print(f"  Exported {len(strings)} strings", file=sys.stderr)


def export_interesting(proj, cfg, name):
    path = get_output_path(name, "_interesting.txt")
    print(f"  Analyzing interesting patterns...", file=sys.stderr)

    patterns = {
        "CRYPTO": ["crypt", "encrypt", "decrypt", "aes", "des", "rsa", "md5", "sha"],
        "AUTH": ["password", "passwd", "secret", "key", "token", "auth", "login"],
        "NETWORK": ["socket", "connect", "send", "recv", "http", "url", "dns", "bind"],
        "FILE_IO": ["fopen", "open", "read", "write", "fread", "fwrite"],
        "EXEC": ["exec", "system", "popen", "shell", "cmd", "fork"],
        "MEMORY": ["malloc", "free", "alloc", "memcpy", "mmap", "mprotect"],
        "DANGEROUS": ["strcpy", "sprintf", "gets", "scanf", "strcat", "vsprintf"],
        "DEBUG": ["debug", "log", "print", "error", "assert", "trace"],
    }

    with open(path, "w") as f:
        f.write("Interesting Functions and Patterns (angr)\n")
        f.write("==========================================\n\n")

        for category, keywords in patterns.items():
            matches = []
            for addr, func in cfg.kb.functions.items():
                fname = func.name.lower()
                for kw in keywords:
                    if kw in fname:
                        matches.append(f"  {func.name} @ {hex(func.addr)}")
                        break

            if matches:
                f.write(f"[{category}]\n")
                for m in matches:
                    f.write(m + "\n")
                f.write("\n")


def main():
    if len(sys.argv) < 2:
        print("Usage: analyze_all.py <binary>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]
    name = os.path.basename(binary_path).split(".")[0]

    print(f"=== angr comprehensive analysis ===", file=sys.stderr)
    print(f"Binary: {binary_path}", file=sys.stderr)

    proj = load_project(binary_path)
    print(f"Architecture: {proj.arch.name} ({proj.arch.bits}-bit)", file=sys.stderr)

    print(f"  Running CFGFast...", file=sys.stderr)
    cfg = proj.analyses.CFGFast(normalize=True, data_references=True)
    print(f"  Recovered {len(cfg.kb.functions)} functions", file=sys.stderr)

    export_summary(proj, cfg, name)
    export_decompiled(proj, cfg, name)
    export_functions(proj, cfg, name)
    export_strings(proj, name)
    export_interesting(proj, cfg, name)

    print(f"\n=== Analysis complete ===", file=sys.stderr)


if __name__ == "__main__":
    main()
