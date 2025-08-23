from __future__ import annotations

import argparse
import json
from time import perf_counter_ns
from typing import List, Tuple

import psutil

from backend.orchestrator import run_bytes

_X86_MOV_RBX_1 = bytes.fromhex("48 C7 C3 01 00 00 00")   
_X86_JMP_SHORT = b"\xEB"                                 
_X86_NOP = b"\x90"

_ARM_B_PLUS4 = bytes.fromhex("01 00 00 14")

def _x86_block_to_next_arm() -> bytes:
    """
    x86 block:
      mov rbx,1        (7B)
      jmp +7           (2B, jumps over 7 pad bytes)
      7 NOPs           (padding)
    -> lands at next 16B boundary where we place the AArch64 'b +4'
    """
    return _X86_MOV_RBX_1 + _X86_JMP_SHORT + b"\x07" + (_X86_NOP * 7)

def build_switch_blob(pairs: int) -> bytes:
    """
    Build a linear program that alternates x86 and AArch64 *sequentially*.
    Each pair contributes two switches: x86->arm (at the ARM block) and
    arm->x86 (after the ARM branch, next x86 block starts).
    The final ARM branch targets the next address (PC+4), which is the end
    of the blob on the last pair, so execution terminates.
    """
    blob = bytearray()
    for _ in range(pairs):
        blob += _x86_block_to_next_arm()
        blob += _ARM_B_PLUS4              
    return bytes(blob)

def measure_switch_latency(pairs: int) -> Tuple[int, List[float]]:
    """
    Run with isa='auto' and record durations between ISA switches
    using the 'on_switch' trace hook.
    """
    blob = build_switch_blob(pairs)

    stamps_ns: List[int] = []

    def tracer(tag: str, data: dict) -> None:
        if tag == "on_switch":
            stamps_ns.append(perf_counter_ns())

    run_bytes(blob, "auto", trace=tracer)

    times_us: List[float] = []
    for a, b in zip(stamps_ns, stamps_ns[1:]):
        times_us.append((b - a) / 1000.0)

    return len(stamps_ns), times_us

def p95(values: List[float]) -> float:
    if not values:
        return 0.0
    vs = sorted(values)
    idx = int(round(0.95 * (len(vs) - 1)))
    return vs[idx]

def main() -> int:
    ap = argparse.ArgumentParser(description="Measure ISA switch latency with dispatcher(auto).")
    ap.add_argument("--pairs", type=int, default=300, help="number of x86<->ARM pairs (default: 300)")
    ap.add_argument("--out", type=str, default="", help="write JSON to this file (else stdout)")
    args = ap.parse_args()

    proc = psutil.Process()

    count, times_us = measure_switch_latency(args.pairs)
    mean_us = (sum(times_us) / len(times_us)) if times_us else 0.0

    median_us = 0.0
    if times_us:
        s = sorted(times_us)
        mid = len(s) // 2
        median_us = (s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2.0)

    p95_us = p95(times_us)

    sps_mean = 1e6 / mean_us if mean_us else 0.0
    sps_median = 1e6 / median_us if median_us else 0.0

    rss_bytes = int(proc.memory_info().rss)

    payload = {
        "pairs": args.pairs,
        "switches": count,
        "samples": len(times_us),
        "mean_us": mean_us,
        "median_us": median_us,
        "p95_us": p95_us,
        "switches_per_sec_mean": sps_mean,
        "switches_per_sec_median": sps_median,
        "rss_bytes": rss_bytes,
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
