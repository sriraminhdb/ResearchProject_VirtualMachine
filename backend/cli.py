from __future__ import annotations

import argparse, json, sys
from typing import Optional, Set, Callable, Dict, Any

from backend.orchestrator import run_bytes
from backend.decoders.arm_to_ir import decode_to_ir as arm_to_ir
from backend.decoders.x86_to_ir import decode_to_ir as x86_to_ir
from backend.tcg_dump import render_tcg

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
    p.add_argument("--emit-tcg", action="store_true", help="Emit TCG representation.")
    p.add_argument("--via-qemu-user", action="store_true", help="Execute the given bytes via qemu-user (TCG) and round-trip core regs.")
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

    if args.emit_tcg:
        pc = 0
        lines = []
        while pc < len(data):
            if args.isa == "arm":
                ir_ops, sz = arm_to_ir(data, pc)
            elif args.isa == "x86":
                ir_ops, sz = x86_to_ir(data, pc)
            else:
                ir_ops, sz = x86_to_ir(data, pc)
                if not ir_ops or sz == 0:
                    ir_ops, sz = arm_to_ir(data, pc)
            if sz <= 0:
                break
            lines += [f"\n# insn @0x{pc:x}, size={sz}"]
            lines += render_tcg(ir_ops, pc=pc)
            pc += sz
        print("\n".join(lines))
        return

    if args.via_qemu_user:
        from backend.executors.qemu_user import run_x86_under_qemu
        if args.isa != "x86":
            raise SystemExit("--via-qemu-user: x86 only in this first cut")
        final_regs = run_x86_under_qemu(data, {})
        result = {
            "isa": "x86",
            "pc": len(data),
            "registers": final_regs,
            "flags": {}
        }
        print(json.dumps(result, indent=2))
        return

if __name__ == "__main__":
    main()
