from __future__ import annotations

from typing import Optional

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64

_x86 = Cs(CS_ARCH_X86, CS_MODE_64)
_x86.detail = False

_arm = Cs(CS_ARCH_ARM64, 0)
_arm.detail = False

_COMMON_ARM = {
    "mov", "movz", "add", "sub", "subs", "cmp", "b", "bl", "cbz", "ret", "nop", "ldr", "str"
}

def _try_x86(code: bytes, pc: int):
    try:
        it = _x86.disasm(code[pc:pc+15], pc)
        insn = next(it, None)
        if insn is None:
            return None
        if 1 <= insn.size <= 15:
            return insn
    except Exception:
        pass
    return None

def _try_arm(code: bytes, pc: int):
    try:
        it = _arm.disasm(code[pc:pc+4], pc)
        insn = next(it, None)
        if insn is None:
            return None
        if insn.size == 4:
            return insn
    except Exception:
        pass
    return None

def detect(mem: bytes, pc: int, *, hint: str | None = None) -> str:
    """
    Super-lightweight heuristic:
      - Prefer strong AArch64 patterns (NOP, MOVZ, B/BL, CBZ/CBNZ)
      - Otherwise accept common x86 bytes (CALL/JMP/Jcc/NOP)
      - Fall back to hint or x86
    """
    b = mem[pc:pc+16]
    if len(b) >= 4:
        w = int.from_bytes(b[:4], "little")

        if w == 0xD503201F:
            return "arm"

        if (w & 0xFFC00000) == 0xD2800000:
            return "arm"

        if (w & 0x7C000000) == 0x14000000 or (w & 0xFC000000) == 0x94000000:
            return "arm"

        if (w & 0x7F000000) == 0x34000000:
            return "arm"

    if b[:1] in (b"\xE8", b"\xE9", b"\xEB", b"\x90"):
        return "x86"
    if len(b) >= 2 and b[0] in (0x0F,) and b[1] in range(0x80, 0x90): 
        return "x86"

    return hint or "x86"
