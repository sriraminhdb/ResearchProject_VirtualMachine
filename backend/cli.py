from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Set, Callable, Dict, Any

from backend.orchestrator import run_bytes

def _read_file(path: str, *, hexfile: bool) -> bytes:
    data = open(path, "rb").read()
    if hexfile:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise SystemExit(f"File {path!r} is not a UTF-8 text hex file; omit --hexfile for raw binary.")
        text = "".join(ch for ch in text if ch not in " \n\r\t")
        if len(text) % 2 != 0:
            raise SystemExit("Odd number of hex digits in --hexfile input.")
        return bytes.fromhex(text)
    return data


def _parse_breakpoints(spec: Optional[str]) -> Set[int]:
    if not spec:
        return set()
    items = [s.strip() for s in spec.split(",") if s.strip()]
    out: Set[int] = set()
    for it in items:
        if it.lower().startswith("0x"):
            out.add(int(it, 16))
        else:
            out.add(int(it))
    return out

def main():
    p = argparse.ArgumentParser(
        prog="python -m backend.cli",
        description="Tiny processor-oriented VM runner (x86/ARM/auto) with optional IR path and tracing.",
    )
    p.add_argument("--isa", required=True, choices=["x86", "arm", "auto"], help="Which ISA backend (or 'auto').")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--hex", help="ASCII hex bytes (spaces allowed).")
    src.add_argument("--file", help="Path to input file (raw or hex with --hexfile).")
    p.add_argument("--hexfile", action="store_true", help="Treat --file contents as ASCII hex instead of raw binary.")
    p.add_argument("--max-steps", type=int, default=100_000, help="Safety step cap.")
    p.add_argument("--breakpoints", type=str, default=None, help="Comma-separated list like '0x10,64'.")
    p.add_argument("--trace", action="store_true", help="Emit trace events.")
    p.add_argument("--json", action="store_true", help="Print JSON of final state + trace.")
    p.add_argument("--use-ir", action="store_true", help="Run through the common IR when available.")
    p.add_argument("--use-jit", action="store_true", help="Execute via LLVM/llvmlite JIT when possible")
    args = p.parse_args()

    if args.hex is not None:
        try:
            data = bytes.fromhex(args.hex.replace(" ", "").replace("\n", ""))
        except ValueError as e:
            raise SystemExit(f"Invalid --hex string: {e}")
    else:
        try:
            data = _read_file(args.file, hexfile=args.hexfile)
        except FileNotFoundError:
            raise SystemExit(f"No such file: {args.file}")
        except OSError as e:
            raise SystemExit(f"Error reading file {args.file!r}: {e}")

    bps = _parse_breakpoints(args.breakpoints)
    trace_log: list[Dict[str, Any]] = []

    def tracer(tag: str, payload: Dict[str, Any]):
        rec: Dict[str, Any] = {"event": tag}
        rec.update(payload or {})
        if "pc" in rec and "pc_after" not in rec:
            rec["pc_after"] = rec["pc"]
        trace_log.append(rec)

    trace_cb: Optional[Callable[[str, dict], None]] = tracer if args.trace else None

    state = run_bytes(
        data,
        args.isa,
        max_steps=args.max_steps,
        breakpoints=bps,
        trace=trace_cb,
        use_ir=args.use_ir or args.use_jit,
        use_jit=args.use_jit,
    )

    if args.json:
        out = {
            "isa": args.isa,
            "pc": state.pc,
            "registers": dict(state.registers),
            "flags": dict(state.flags),
            "code_end": state.code_end,
            "steps": state.flags.get("_steps"),
            "halted": bool(state.flags.get("_halt", False)),
            "break_hit": (state.pc in bps) if bps else False,
            "trace": trace_log if args.trace else None,
        }
        print(json.dumps(out, indent=2))
    else:
        print(f"ISA: {args.isa}")
        print(f" PC={state.pc} end={state.code_end} halted={state.flags.get('_halt', False)}")
        print(f" Registers: {state.registers}")
        print(f" Flags    : {state.flags}")
        if args.trace:
            print("\nTrace:")
            for e in trace_log:
                print(e)

if __name__ == "__main__":
    main()
