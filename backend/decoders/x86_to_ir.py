from __future__ import annotations
from typing import List, Tuple

from backend.core.ir import IROp, NOP, MOV, CMP, JE, JMP

def _u8(b: int) -> int:
    return b & 0xFF

def _s8(b: int) -> int:
    b &= 0xFF
    return b - 256 if b & 0x80 else b

def _u32(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)

def _u64(b: bytes) -> int:
    return int.from_bytes(b, "little", signed=False)

def decode_to_ir(code: bytes, pc: int) -> Tuple[List[IROp], int]:
    """
    Minimal x86-64 decoder for a few patterns used in tests:
      - 90                 : NOP
      - 48 C7 C3 imm32     : MOV RBX, imm32
      - 48 83 F8 ib        : CMP RAX, imm8
      - 74 cb              : JE short
      - EB cb              : JMP short
      - 48 B8 imm64        : MOV RAX, imm64   (optional convenience)
    Returns (ops, size). Targets are absolute PCs.
    """
    i = pc
    n = len(code)

    def need(k: int) -> bool:
        return (i + k) <= n

    if need(1) and code[i] == 0x90:
        return [NOP(size=1)], 1

    if need(7) and code[i:i+3] == b"\x48\xC7\xC3":
        imm = _u32(code[i+3:i+7])
        return [MOV(size=7, dst="rbx", src_imm=imm)], 7

    if need(10) and code[i:i+2] == b"\x48\xB8":
        imm = _u64(code[i+2:i+10])
        return [MOV(size=10, dst="rax", src_imm=imm)], 10

    if need(4) and code[i:i+3] == b"\x48\x83\xF8":
        imm8 = _s8(code[i+3])
        return [CMP(size=4, a_reg="rax", b_imm=imm8)], 4

    if need(2) and code[i] == 0x74:
        rel = _s8(code[i+1])
        target = i + 2 + rel
        return [JE(size=2, target=target)], 2

    if need(2) and code[i] == 0xEB:
        rel = _s8(code[i+1])
        target = i + 2 + rel
        return [JMP(size=2, target=target)], 2

    return [], 0
