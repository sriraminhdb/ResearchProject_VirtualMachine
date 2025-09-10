# bench/microbenches.py
from __future__ import annotations
from typing import Dict, List, Tuple

# Reuse the exact blobs from your tests to keep things stable
X_SET_RBX_RDX = bytes.fromhex("48 C7 C3 2A 00 00 00 48 C7 C2 09 00 00 00 C3")
X_INC_RBX      = bytes.fromhex("48 FF C3 C3")

A_SET_X1_X2    = bytes.fromhex("41 05 80 D2 22 01 80 D2 C0 03 5F D6")
A_SET_X1_X2_ALT= bytes.fromhex("41 05 80 D2 22 00 80 D2 C0 03 5F D6")
A_ADD2_X1      = bytes.fromhex("21 08 00 91 C0 03 5F D6")


def scenario_no_switch_x86(n: int) -> Tuple[List[bytes], Dict[str, int], str]:
    chunks: List[bytes] = []
    chunks.append(b"X" + X_SET_RBX_RDX)
    for _ in range(n):
        chunks.append(b"X" + X_INC_RBX)
    regs0 = {"rbx": 0, "rdx": 0, "x1": 0, "x2": 0}
    return chunks, regs0, f"x86_noswitch_{n}"


def scenario_no_switch_arm(n: int, use_alt_set: bool = False) -> Tuple[List[bytes], Dict[str, int], str]:
    chunks: List[bytes] = []
    chunks.append(b"A" + (A_SET_X1_X2_ALT if use_alt_set else A_SET_X1_X2))
    for _ in range(n):
        chunks.append(b"A" + A_ADD2_X1)
    regs0 = {"rbx": 0, "rdx": 0, "x1": 0, "x2": 0}
    tag = "arm_noswitch_alt" if use_alt_set else "arm_noswitch"
    return chunks, regs0, f"{tag}_{n}"


def scenario_alternating(n_cycles: int) -> Tuple[List[bytes], Dict[str, int], str]:
    chunks: List[bytes] = []
    for _ in range(n_cycles):
        chunks.extend([
            b"X" + X_SET_RBX_RDX,
            b"A" + A_SET_X1_X2,
            b"X" + X_INC_RBX,
            b"A" + A_ADD2_X1,
        ])
    regs0 = {"rbx": 0, "rdx": 0, "x1": 0, "x2": 0}
    return chunks, regs0, f"alternating_{n_cycles}"


# --------- NEW: memtouch helpers (for cache/working-set tests) ----------------
_MEMTOUCH_MAGIC = b"MTCH"

def memtouch_chunk(isa: str, size: int, iters: int, stride: int) -> bytes:
    """
    Build a 'memtouch' micro-op chunk recognized by the LLVM mini-jit:
      payload = b"MTCH" + size:u64 + iters:u64 + stride:u64
    Prefixed with 'X' or 'A' so the ISA detector keeps working.
    """
    prefix = b"X" if isa.startswith("x") else b"A"
    payload = (
        _MEMTOUCH_MAGIC +
        size.to_bytes(8, "little") +
        iters.to_bytes(8, "little") +
        stride.to_bytes(8, "little")
    )
    return prefix + payload


def scenario_memtouch(isa: str, sizes: List[int], bytes_total: int = 8*1024*1024, stride: int = 64) -> Tuple[List[bytes], Dict[str, int], str]:
    """
    For each working-set size, create one memtouch chunk. The number of iterations
    is chosen so each size touches ~bytes_total in total to normalize work.
    """
    assert sizes, "sizes must be non-empty"
    chunks: List[bytes] = []
    for sz in sizes:
        if sz <= 0:
            continue
        steps_per_iter = max(1, sz // max(stride, 1))
        iters = max(1, (bytes_total // max(stride, 1)) // steps_per_iter)
        chunks.append(memtouch_chunk(isa, sz, iters, stride))
    regs0 = {"rbx": 0, "rdx": 0, "x1": 0, "x2": 0}
    tag = f"{'x86' if isa.startswith('x') else 'arm'}_memtouch_{'_'.join(str(s) for s in sizes)}_s{stride}"
    return chunks, regs0, tag
