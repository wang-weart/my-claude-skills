#!/usr/bin/env python3
"""Extract ASCII and Unicode strings from binary sections."""

import sys
import os
import json

import angr


def extract_strings(data, base_addr, section_name, min_length=4):
    """Extract printable ASCII strings from raw bytes."""
    strings = []
    current = bytearray()
    start_addr = None

    for i, byte in enumerate(data):
        if 0x20 <= byte <= 0x7E:
            if not current:
                start_addr = base_addr + i
            current.append(byte)
        else:
            if len(current) >= min_length:
                try:
                    s = current.decode("ascii")
                    strings.append({
                        "address": hex(start_addr),
                        "value": s[:1000],
                        "length": len(s),
                        "section": section_name,
                        "encoding": "ascii",
                    })
                except Exception:
                    pass
            current = bytearray()
            start_addr = None

    # Handle string at end of section
    if len(current) >= min_length:
        try:
            s = current.decode("ascii")
            strings.append({
                "address": hex(start_addr),
                "value": s[:1000],
                "length": len(s),
                "section": section_name,
                "encoding": "ascii",
            })
        except Exception:
            pass

    return strings


def main():
    if len(sys.argv) < 2:
        print("Usage: export_strings.py <binary>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]
    name = os.path.basename(binary_path).split(".")[0]
    output_dir = os.environ.get("ANGR_OUTPUT_DIR", ".")
    auto_load = os.environ.get("ANGR_AUTO_LOAD_LIBS", "false").lower() == "true"
    output_path = os.path.join(output_dir, f"{name}_strings.json")

    kwargs = {"auto_load_libs": auto_load}
    base = os.environ.get("ANGR_BASE_ADDR", "")
    if base:
        kwargs["main_opts"] = {"base_addr": int(base, 0)}

    print(f"Loading {binary_path}...", file=sys.stderr)
    proj = angr.Project(binary_path, **kwargs)

    obj = proj.loader.main_object
    all_strings = []

    if hasattr(obj, "sections") and obj.sections:
        for sec in obj.sections:
            if sec.memsize == 0:
                continue
            # Focus on data sections for strings
            try:
                data = proj.loader.memory.load(sec.vaddr, min(sec.memsize, 10 * 1024 * 1024))
                found = extract_strings(data, sec.vaddr, sec.name)
                all_strings.extend(found)
            except Exception:
                continue
    else:
        # Fallback: scan all loaded memory
        for seg in (obj.segments if hasattr(obj, "segments") and obj.segments else []):
            try:
                data = proj.loader.memory.load(seg.vaddr, min(seg.memsize, 10 * 1024 * 1024))
                found = extract_strings(data, seg.vaddr, "segment")
                all_strings.extend(found)
            except Exception:
                continue

    with open(output_path, "w") as f:
        json.dump(all_strings, f, indent=2)

    print(f"Exported {len(all_strings)} strings to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
