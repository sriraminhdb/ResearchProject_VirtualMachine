from __future__ import annotations

import argparse
import json
import statistics
import sys
from time import perf_counter_ns
from typing import Dict, List

import psutil

from backend.orchestrator import run_bytes

def _peak_rss_linux_bytes() -> int:
    try:
        with open("/proc/self/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    # e.g. "VmHWM:\t  123456 kB"
                    kb = int(line.split()[1])
                    return kb * 1024
    except Exception:
        pass
    return 0

def build_x86_program(repeats: int) -> bytes:
    """
    Repeat an IR/JIT-supported x86-64 instruction.
    'mov rbx, imm32' (7 bytes) is safe across paths.
    """
    insn = bytes.fromhex("48 C7 C3 07 00 00 00")
    return insn * repeats

def build_arm_program(repeats: int) -> bytes:
    """
    Repeat an IR/JIT-supported AArch64 instruction.
    'movz x1,#42' (4 bytes).
    """
    insn = bytes.fromhex("41 05 80 D2")
    return insn * repeats

def p95(values: List[float]) -> float:
    if not values:
        return 0.0
    vs = sorted(values)
    idx = int(round(0.95 * (len(vs) - 1)))
    return vs[idx]

def time_case(
    program: bytes,
    isa: str,
    *,
    runs: int,
    use_ir: bool,
    use_jit: bool,
    repeats: int,
) -> Dict[str, float]:
    """
    Warm up once, then run N+1 times and drop the first timed run to
    reduce JIT/cache effects in steady-state stats.
    """

    run_bytes(program, isa, use_ir=use_ir, use_jit=use_jit)

    times_us: List[float] = []
    total_runs = runs + 1

    for _ in range(total_runs):
        t0 = perf_counter_ns()
        run_bytes(program, isa, use_ir=use_ir, use_jit=use_jit)
        t1 = perf_counter_ns()
        times_us.append((t1 - t0) / 1000.0)

    times_us = times_us[1:]

    mean_us = float(statistics.fmean(times_us))
    median_us = float(statistics.median(times_us))
    p95_val = float(p95(times_us))

    ips_mean = (repeats * 1e6) / mean_us if mean_us else 0.0
    ips_median = (repeats * 1e6) / median_us if median_us else 0.0

    return {
        "runs": runs,
        "instrs_per_run": repeats,
        "mean_us": mean_us,
        "median_us": median_us,
        "p95_us": p95_val,
        "ips_mean": ips_mean,
        "ips_median": ips_median,
    }

def speedup(native: Dict[str, float], other: Dict[str, float]) -> float:
    """Median-based speedup for robustness."""
    n = native.get("median_us", 0.0)
    o = other.get("median_us", 0.0)
    return (n / o) if (o and n) else 0.0

def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Benchmark native vs IR vs JIT on x86 and ARM.")
    ap.add_argument("--runs", type=int, default=30, help="timed runs per case (default: 30)")
    ap.add_argument("--repeats", type=int, default=2000,
                    help="instructions per test program (default: 2000)")
    ap.add_argument("--out", type=str, default="",
                    help="write JSON to this file (else prints to stdout)")
    args = ap.parse_args(argv)

    proc = psutil.Process()
    rss_start = int(proc.memory_info().rss)

    meta = {
        "platform": sys.platform,
        "python": ".".join(map(str, sys.version_info[:3])),
        "runs_per_case": args.runs,
        "repeats": args.repeats,
        "rss_bytes_start": rss_start,
    }

    prog_x86 = build_x86_program(args.repeats)
    prog_arm = build_arm_program(args.repeats)

    results: Dict[str, Dict[str, float]] = {}

    results["x86_native"] = time_case(prog_x86, "x86", runs=args.runs, use_ir=False, use_jit=False, repeats=args.repeats)
    results["x86_ir"]     = time_case(prog_x86, "x86", runs=args.runs, use_ir=True,  use_jit=False, repeats=args.repeats)
    results["x86_jit"]    = time_case(prog_x86, "x86", runs=args.runs, use_ir=False, use_jit=True,  repeats=args.repeats)

    results["arm_native"] = time_case(prog_arm, "arm", runs=args.runs, use_ir=False, use_jit=False, repeats=args.repeats)
    results["arm_ir"]     = time_case(prog_arm, "arm", runs=args.runs, use_ir=True,  use_jit=False, repeats=args.repeats)
    results["arm_jit"]    = time_case(prog_arm, "arm", runs=args.runs, use_ir=False, use_jit=True,  repeats=args.repeats)

    speedups = {
        "x86_ir":  speedup(results["x86_native"], results["x86_ir"]),
        "x86_jit": speedup(results["x86_native"], results["x86_jit"]),
        "arm_ir":  speedup(results["arm_native"], results["arm_ir"]),
        "arm_jit": speedup(results["arm_native"], results["arm_jit"]),
    }

    meta["rss_bytes_end"] = int(proc.memory_info().rss)
    meta["rss_bytes_peak"] = _peak_rss_linux_bytes()

    payload = {
        "meta": meta,
        **results,
        "speedup_vs_native": speedups,
    }

    text = json.dumps(payload, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text, flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
