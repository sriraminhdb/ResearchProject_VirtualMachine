from __future__ import annotations
import argparse, json, statistics, sys, os
from time import perf_counter_ns
from typing import Dict, List

from backend.orchestrator import run_bytes

def build_x86_program(repeats: int) -> bytes:
    insn = bytes.fromhex("48 C7 C3 07 00 00 00")
    return insn * repeats

def build_arm_program(repeats: int) -> bytes:
    insn = bytes.fromhex("41 05 80 D2")
    return insn * repeats

def p95(values: List[float]) -> float:
    if not values:
        return 0.0
    vs = sorted(values)
    idx = int(round(0.95 * (len(vs) - 1)))
    return vs[idx]

def _read_proc_status() -> Dict[str,int]:
    out: Dict[str,int] = {}
    try:
        with open("/proc/self/status","r",encoding="utf-8") as f:
            for ln in f:
                if ln.startswith(("VmRSS:", "VmHWM:")):
                    k, v = ln.split(":",1)
                    num = int(v.strip().split()[0])  # kB
                    out[k] = num * 1024
    except Exception:
        pass
    return out

def time_case(program: bytes, isa: str, *, runs: int, use_ir: bool, use_jit: bool) -> Dict[str, float]:
    """
    Warm up once, then run N+1 times and drop the first timed run to
    remove JIT compilation / cache effects from steady-state stats.
    Also tracks per-case peak RSS delta (VmHWM diff).
    """
    run_bytes(program, isa, use_ir=use_ir, use_jit=use_jit)

    times_us: List[float] = []
    total_runs = runs + 1

    rss0 = _read_proc_status().get("VmHWM", 0)

    for _ in range(total_runs):
        t0 = perf_counter_ns()
        run_bytes(program, isa, use_ir=use_ir, use_jit=use_jit)
        t1 = perf_counter_ns()
        times_us.append((t1 - t0) / 1000.0)

    times_us = times_us[1:]

    rss1 = _read_proc_status().get("VmHWM", 0)
    peak_delta = max(0, rss1 - rss0)

    instr_size = 4 if isa == "arm" else 7
    instrs_per_run = len(program) // instr_size
    mean_us = float(statistics.fmean(times_us))
    median_us = float(statistics.median(times_us))

    return {
        "runs": runs,
        "instrs_per_run": instrs_per_run,
        "mean_us": mean_us,
        "median_us": median_us,
        "p95_us": float(p95(times_us)),
        "ips_mean": float(instrs_per_run / (mean_us / 1e6)),
        "ips_median": float(instrs_per_run / (median_us / 1e6)),
        "peak_rss_bytes": int(peak_delta),
    }

def speedup(native: Dict[str, float], other: Dict[str, float]) -> float:
    n = native["median_us"]
    o = other["median_us"]
    return (n / o) if o > 0 else 0.0

def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Benchmark native vs IR vs JIT on x86 and ARM.")
    ap.add_argument("--runs", type=int, default=30, help="timed runs per case (default: 30)")
    ap.add_argument("--repeats", type=int, default=2000,
                    help="how many instructions to place in the test program (default: 2000)")
    ap.add_argument("--out", type=str, default="",
                    help="write JSON to this file (else prints to stdout)")
    args = ap.parse_args(argv)

    meta = {
        "platform": sys.platform,
        "python": ".".join(map(str, sys.version_info[:3])),
        "runs_per_case": args.runs,
        "repeats": args.repeats,
    }

    prog_x86 = build_x86_program(args.repeats)
    prog_arm = build_arm_program(args.repeats)

    rss_start = _read_proc_status().get("VmRSS", 0)

    results: Dict[str, Dict[str, float]] = {}

    results["x86_native"] = time_case(prog_x86, "x86", runs=args.runs, use_ir=False, use_jit=False)
    results["x86_ir"]     = time_case(prog_x86, "x86", runs=args.runs, use_ir=True,  use_jit=False)
    results["x86_jit"]    = time_case(prog_x86, "x86", runs=args.runs, use_ir=False, use_jit=True)

    results["arm_native"] = time_case(prog_arm, "arm", runs=args.runs, use_ir=False, use_jit=False)
    results["arm_ir"]     = time_case(prog_arm, "arm", runs=args.runs, use_ir=True,  use_jit=False)
    results["arm_jit"]    = time_case(prog_arm, "arm", runs=args.runs, use_ir=False, use_jit=True)

    speedups = {
        "x86_ir":  speedup(results["x86_native"], results["x86_ir"]),
        "x86_jit": speedup(results["x86_native"], results["x86_jit"]),
        "arm_ir":  speedup(results["arm_native"], results["arm_ir"]),
        "arm_jit": speedup(results["arm_native"], results["arm_jit"]),
    }

    payload = {
        "meta": meta,
        **results,
        "speedup_vs_native": speedups,
    }

    rss_end  = _read_proc_status().get("VmRSS", 0)
    rss_peak = _read_proc_status().get("VmHWM", 0)
    payload["meta"]["rss_bytes_start"] = int(rss_start)
    payload["meta"]["rss_bytes_end"]   = int(rss_end)
    payload["meta"]["rss_bytes_peak"]  = int(rss_peak)

    text = json.dumps(payload, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text, flush=True)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
