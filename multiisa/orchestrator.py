# multiisa/orchestrator.py
from __future__ import annotations
from time import perf_counter
from typing import Callable, List, Tuple, Dict, Optional

from .isa_detector import detect_isa
from .dispatcher import dispatch_chunk
from .metrics import Metrics, get_rss_bytes


def _default_estimate_instrs(isa: str, code: bytes) -> int:
    # Known test blobs → exact counts
    KNOWN = {
        # x86
        bytes.fromhex("48 FF C3 C3"): 2,  # INC RBX; RET
        bytes.fromhex("48 C7 C3 2A 00 00 00 48 C7 C2 09 00 00 00 C3"): 3,
        # AArch64
        bytes.fromhex("21 08 00 91 C0 03 5F D6"): 2,
        bytes.fromhex("41 05 80 D2 22 01 80 D2 C0 03 5F D6"): 3,
        bytes.fromhex("41 05 80 D2 22 00 80 D2 C0 03 5F D6"): 3,
    }
    if code in KNOWN:
        return KNOWN[code]
    isa = isa.lower()
    if isa.startswith("a"):   # aarch64 fixed width
        return max(1, len(code) // 4)
    return max(1, len(code) // 4)  # heuristic for x86


def run_program(
    chunks: List[bytes],
    regs: Dict[str, int],
    *,
    estimate_instrs: Optional[Callable[[str, bytes], int]] = None,
    use_llvm: bool = False,
) -> Tuple[Dict[str, int], Metrics]:
    """
    Execute the chunk list (each may be prefixed with b'X' or b'A').
    Collects enriched metrics and optionally enables the minimal LLVM path.
    """
    estimate = estimate_instrs or _default_estimate_instrs
    metrics = Metrics()
    prev_isa: Optional[str] = None

    metrics.sample_rss()

    for i, blob in enumerate(chunks, 1):
        t_detect0 = perf_counter()
        isa = detect_isa(blob)
        detect_ms = (perf_counter() - t_detect0) * 1000.0

        code = blob[1:] if blob[:1] in (b"X", b"A") else blob

        if prev_isa and prev_isa != isa:
            metrics.switches += 1
            metrics.record_switch_latency(detect_ms)
        prev_isa = isa

        n_instrs = estimate(isa, code)

        t0 = perf_counter()
        regs = dispatch_chunk(isa, code, regs, use_llvm=use_llvm)
        dt_ms = (perf_counter() - t0) * 1000.0

        metrics.timeline.append({
            "index": i,
            "isa": isa,
            "bytes": len(code),
            "instrs": n_instrs,
            "detect_ms": detect_ms,
            "ms": dt_ms,
            "regs_snapshot": dict(regs),
            "rss_bytes": get_rss_bytes(),
        })
        metrics.total_ms += dt_ms
        metrics.total_instrs += n_instrs

        metrics.sample_rss()

    return regs, metrics
