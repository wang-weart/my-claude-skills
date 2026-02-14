#!/usr/bin/env python3
"""Symbolic execution: find inputs that reach target addresses."""

import sys
import os
import json
import argparse

import angr
import claripy


def main():
    parser = argparse.ArgumentParser(
        description="Symbolic execution with angr: find inputs reaching target addresses"
    )
    parser.add_argument("binary", help="Path to the binary")
    parser.add_argument("--find", required=True, action="append",
                        help="Target address(es) to reach (hex). Can be repeated.")
    parser.add_argument("--avoid", action="append", default=[],
                        help="Address(es) to avoid (hex). Can be repeated.")
    parser.add_argument("--timeout", type=int, default=300,
                        help="Exploration timeout in seconds (default: 300)")
    parser.add_argument("--stdin-size", type=int, default=64,
                        help="Size of symbolic stdin in bytes (default: 64)")
    parser.add_argument("--start", default=None,
                        help="Start address (hex). Default: entry point")

    args = parser.parse_args()

    binary_path = args.binary
    name = os.path.basename(binary_path).split(".")[0]
    output_dir = os.environ.get("ANGR_OUTPUT_DIR", ".")
    auto_load = os.environ.get("ANGR_AUTO_LOAD_LIBS", "false").lower() == "true"
    output_path = os.path.join(output_dir, f"{name}_symbolic.json")

    find_addrs = [int(a, 0) for a in args.find]
    avoid_addrs = [int(a, 0) for a in args.avoid]

    kwargs = {"auto_load_libs": auto_load}
    base = os.environ.get("ANGR_BASE_ADDR", "")
    if base:
        kwargs["main_opts"] = {"base_addr": int(base, 0)}

    print(f"Loading {binary_path}...", file=sys.stderr)
    proj = angr.Project(binary_path, **kwargs)

    print(f"Target address(es): {[hex(a) for a in find_addrs]}", file=sys.stderr)
    print(f"Avoid address(es): {[hex(a) for a in avoid_addrs]}", file=sys.stderr)
    print(f"Timeout: {args.timeout}s", file=sys.stderr)

    # Create initial state
    if args.start:
        start_addr = int(args.start, 0)
        state = proj.factory.blank_state(addr=start_addr)
        print(f"Starting from: {hex(start_addr)}", file=sys.stderr)
    else:
        state = proj.factory.entry_state()
        print(f"Starting from entry point: {hex(proj.entry)}", file=sys.stderr)

    # Create simulation manager
    simgr = proj.factory.simgr(state)

    print(f"Exploring...", file=sys.stderr)
    simgr.explore(
        find=find_addrs,
        avoid=avoid_addrs,
        timeout=args.timeout,
    )

    result = {
        "binary": os.path.basename(binary_path),
        "find_addresses": [hex(a) for a in find_addrs],
        "avoid_addresses": [hex(a) for a in avoid_addrs],
        "found_count": len(simgr.found),
        "avoided_count": len(simgr.avoid) if hasattr(simgr, "avoid") else 0,
        "active_count": len(simgr.active),
        "deadended_count": len(simgr.deadended),
        "found_states": [],
    }

    if simgr.found:
        print(f"\nFound {len(simgr.found)} state(s) reaching target!", file=sys.stderr)

        for i, found_state in enumerate(simgr.found[:10]):
            state_info = {
                "state_index": i,
                "address": hex(found_state.addr),
            }

            # Try to get stdin
            try:
                stdin_data = found_state.posix.dumps(0)
                state_info["stdin"] = stdin_data.decode("latin-1")
                state_info["stdin_hex"] = stdin_data.hex()
            except Exception:
                state_info["stdin"] = None

            # Try to get stdout
            try:
                stdout_data = found_state.posix.dumps(1)
                state_info["stdout"] = stdout_data.decode("latin-1")
            except Exception:
                state_info["stdout"] = None

            # Constraint count
            try:
                state_info["constraint_count"] = len(found_state.solver.constraints)
            except Exception:
                pass

            result["found_states"].append(state_info)
    else:
        print(f"\nNo states found reaching target addresses.", file=sys.stderr)
        print(f"  Active paths: {len(simgr.active)}", file=sys.stderr)
        print(f"  Dead-ended paths: {len(simgr.deadended)}", file=sys.stderr)

    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"Output: {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
