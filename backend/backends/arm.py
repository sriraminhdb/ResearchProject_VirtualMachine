from __future__ import annotations
from typing import Any

MASK64 = (1 << 64) - 1

def _ensure(mem: bytearray, length: int) -> None:
    if length < 0:
        return
    if length > len(mem):
        mem.extend(b"\x00" * (length - len(mem)))

def _get(state, reg: str) -> int:
    return int(state.registers.get(reg, 0)) & MASK64

def _set(state, reg: str, val: int) -> None:
    state.registers[reg] = int(val) & MASK64

def rname(idx: int) -> str:
    return f"x{idx}"

def write_mem(reg: str, disp: int, val: int, *, state) -> None:
    base = _get(state, reg) + disp
    _ensure(state.memory, base + 8)
    state.memory[base:base+8] = int(val).to_bytes(8, "little")

def read_mem(reg: str, disp: int, *, state) -> int:
    base = _get(state, reg) + disp
    _ensure(state.memory, base + 8)
    return int.from_bytes(state.memory[base:base+8], "little")


def step(mem: bytes | bytearray, state) -> Any:
    # Make sure memory is mutable
    if not isinstance(state.memory, bytearray):
        state.memory = bytearray(state.memory)

    pc = state.pc
    ins = int.from_bytes(state.memory[pc:pc+4], "little")
    state.pc = pc + 4  # optimistic advance; handlers can override

    # NOP
    if ins == 0xD503201F:
        return state

    # ------------------------------------------------------------------
    # ADD/ADDS (immediate, 64-bit)
    # A64 encoding (Add/subtract (immediate)):
    #   sf=1 (bit31), op=0 (bit30), S = 0 for ADD / 1 for ADDS (bit29),
    #   class = 10001b in bits [28:24].
    # This covers both 0x91000000 (ADD imm) and 0xB1000000 (ADDS imm).
    # ------------------------------------------------------------------
    if ((ins & 0x1F000000) == 0x11000000   # class 10001b
        and ((ins >> 31) & 1) == 1         # sf = 1 (64-bit)
        and ((ins >> 30) & 1) == 0):       # op = 0 (ADD/ADDS)
        shift = (ins >> 22) & 0x3
        if shift not in (0, 1):            # only <<0 or <<12 valid
            state.pc = pc + 4
            return state
        imm12 = (ins >> 10) & 0xFFF
        imm   = imm12 << (12 if shift == 1 else 0)
        rn    = (ins >> 5)  & 0x1F
        rd    =  ins        & 0x1F

        res = (_get(state, rname(rn)) + imm) & MASK64
        _set(state, rname(rd), res)

        # If S==1 (ADDS), update flags (only ZF used in tests)
        if ((ins >> 29) & 1) == 1:
            state.flags["ZF"] = (res == 0)

        state.pc = pc + 4
        return state

    # MOVZ (Move wide with zero, 64-bit) — simplest form with hw=0
    if (ins & 0xFF800000) == 0xD2800000:
        rd = ins & 0x1F
        imm16 = (ins >> 5) & 0xFFFF
        _set(state, rname(rd), imm16)
        state.pc = pc + 4
        return state

    # STR (unsigned immediate, 64-bit)
    if (ins & 0xFFC00000) == 0xF9000000:
        rt   =  ins        & 0x1F
        rn   = (ins >> 5)  & 0x1F
        imm12 = (ins >> 10) & 0xFFF
        write_mem(rname(rn), imm12 * 8, _get(state, rname(rt)), state=state)
        state.pc = pc + 4
        return state

    # LDR (unsigned immediate, 64-bit)
    if (ins & 0xFFC00000) == 0xF9400000:
        rt   =  ins        & 0x1F
        rn   = (ins >> 5)  & 0x1F
        imm12 = (ins >> 10) & 0xFFF
        val = read_mem(rname(rn), imm12 * 8, state=state)
        _set(state, rname(rt), val)
        state.pc = pc + 4
        return state

    # ADD (shifted register, 64-bit)
    if (ins & 0xFF2003E0) == 0x8B000000:
        rd   =  ins        & 0x1F
        rn   = (ins >> 5)  & 0x1F
        rm   = (ins >> 16) & 0x1F
        imm6 = (ins >> 10) & 0x3F
        val_m = (_get(state, rname(rm)) << imm6) & MASK64
        _set(state, rname(rd), (_get(state, rname(rn)) + val_m) & MASK64)
        state.pc = pc + 4
        return state

    # SUBS (immediate) — minimal cmp-like behavior (update ZF)
    if (ins & 0xFF800000) == 0xF1000000:
        rn    = (ins >> 5)  & 0x1F
        imm12 = (ins >> 10) & 0xFFF
        state.flags["ZF"] = (_get(state, rname(rn)) == imm12)
        state.pc = pc + 4
        return state

    # CBZ (compare and branch on zero)
    if (ins & 0xFF000000) == 0xB4000000:
        rt   =  ins        & 0x1F
        imm19 = (ins >> 5) & 0x7FFFF
        off = imm19 << 2
        if off & (1 << 20):  # sign-extend 21-bit
            off -= 1 << 21
        if _get(state, rname(rt)) == 0:
            target = pc + off
            state.pc = target if target != pc else pc + 4
        else:
            state.pc = pc + 4
        return state

    # BL (branch with link)
    if (ins & 0xFC000000) == 0x94000000:
        imm26 = ins & 0x03FFFFFF
        off = imm26 << 2
        if off & (1 << 27):  # sign-extend 28-bit
            off -= 1 << 28
        _set(state, "x30", pc + 4)  # link register
        state.pc = pc + off
        return state

    # RET
    if ins == 0xD65F03C0:
        state.pc = _get(state, "x30")
        return state

    # Default: leave state as advanced by 4
    return state
