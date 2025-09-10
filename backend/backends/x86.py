from __future__ import annotations
from typing import Any

MASK64 = (1 << 64) - 1

def _ensure(mem: bytearray, length: int) -> None:
    if length > len(mem):
        mem.extend(b"\x00" * (length - len(mem)))

def _read64(mem: bytearray, addr: int) -> int:
    _ensure(mem, addr + 8)
    return int.from_bytes(mem[addr:addr+8], "little")

def _write64(mem: bytearray, addr: int, val: int) -> None:
    _ensure(mem, addr + 8)
    mem[addr:addr+8] = int(val & MASK64).to_bytes(8, "little")

def _get(state, reg: str) -> int:
    return int(state.registers.get(reg, 0)) & MASK64

def _set(state, reg: str, val: int) -> None:
    state.registers[reg] = int(val) & MASK64

def _sx8(x: int) -> int:
    return x - 0x100 if x & 0x80 else x

def _sx32(x: int) -> int:
    return x - 0x1_0000_0000 if x & 0x8000_0000 else x

def _ensure_stack(state) -> None:
    if "rsp" not in state.registers:
        state.registers["rsp"] = 0x1000
    state.registers.setdefault("rbp", state.registers["rsp"])
    state.registers["sp"] = state.registers["rsp"]

def _reg_name_from_low3(low3: int) -> str:
    return ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][low3 & 7]

def step(mem: bytes | bytearray, state) -> Any:
    if not isinstance(state.memory, bytearray):
        state.memory = bytearray(state.memory)

    pc = state.pc
    m = state.memory

    if pc >= len(m):
        return state

    b0 = m[pc]

    if b0 == 0x90:
        state.pc = pc + 1
        return state

    if b0 == 0xC3:
        _ensure_stack(state)
        ret = _read64(m, _get(state, "rsp"))
        state.registers["rsp"] = _get(state, "rsp") + 8
        state.pc = ret
        return state

    if b0 == 0xC2 and pc + 3 <= len(m):
        _ensure_stack(state)
        imm16 = int.from_bytes(m[pc+1:pc+3], "little")
        ret = _read64(m, _get(state, "rsp"))
        state.registers["rsp"] = _get(state, "rsp") + 8 + imm16
        state.pc = ret
        return state

    if b0 == 0xC9:
        _ensure_stack(state)
        state.registers["rsp"] = _get(state, "rbp")
        new_rbp = _read64(m, _get(state, "rsp"))
        state.registers["rsp"] = _get(state, "rsp") + 8
        _set(state, "rbp", new_rbp)
        state.pc = pc + 1
        return state

    if b0 == 0xE9 and pc + 5 <= len(m):
        disp = _sx32(int.from_bytes(m[pc+1:pc+5], "little"))
        state.pc = (pc + 5) + disp
        return state

    if b0 == 0xE8 and pc + 5 <= len(m):
        _ensure_stack(state)
        disp = _sx32(int.from_bytes(m[pc+1:pc+5], "little"))
        ret = pc + 5
        rsp = _get(state, "rsp") - 8
        _write64(m, rsp, ret)
        state.registers["rsp"] = rsp
        state.pc = ret + disp
        return state

    if b0 == 0x74 and pc + 2 <= len(m):
        rel = _sx8(m[pc+1])
        if state.flags.get("ZF", False):
            state.pc = (pc + 2) + rel
        else:
            state.pc = pc + 2
        return state

    if pc + 2 <= len(m) and m[pc] == 0x48:
        op1 = m[pc+1]

        if op1 == 0xB8 and pc + 10 <= len(m):
            imm = int.from_bytes(m[pc+2:pc+10], "little")
            _set(state, "rax", imm)
            state.pc = pc + 10
            return state

        if op1 == 0xC7 and pc + 7 <= len(m):
            modrm = m[pc+2]
            mod = (modrm >> 6) & 3
            regop = (modrm >> 3) & 7
            rm = modrm & 7
            if regop == 0 and mod == 3:
                dst = _reg_name_from_low3(rm)
                imm = int.from_bytes(m[pc+3:pc+7], "little", signed=False)
                if imm & 0x8000_0000:
                    imm = imm - 0x1_0000_0000
                _set(state, dst, imm)
                state.pc = pc + 7
                return state

        if op1 == 0x05 and pc + 6 <= len(m):
            imm = int.from_bytes(m[pc+2:pc+6], "little", signed=True)
            _set(state, "rax", _get(state, "rax") + imm)
            state.pc = pc + 6
            return state

        if op1 == 0x01 and pc + 3 <= len(m):
            modrm = m[pc+2]
            mod = (modrm >> 6) & 3
            reg = (modrm >> 3) & 7
            rm  = modrm & 7
            src = _reg_name_from_low3(reg)
            if mod == 3:
                dst = _reg_name_from_low3(rm)
                _set(state, "rax" if dst == "rax" else dst, _get(state, dst) + _get(state, src))
                state.pc = pc + 3
                return state

        if op1 == 0xFF and pc + 3 <= len(m):
            modrm = m[pc+2]
            op = (modrm >> 3) & 7
            mod = (modrm >> 6) & 3
            rm  = modrm & 7
            if op == 0 and mod == 3:
                reg = _reg_name_from_low3(rm)
                _set(state, reg, _get(state, reg) + 1)
                state.pc = pc + 3
                return state

        if op1 == 0x89 and pc + 3 <= len(m):
            modrm = m[pc+2]
            mod = (modrm >> 6) & 3
            reg = (modrm >> 3) & 7
            rm  = modrm & 7
            src = _reg_name_from_low3(reg)
            if mod == 0:
                base = _reg_name_from_low3(rm)
                addr = _get(state, base)
                _write64(m, addr, _get(state, src))
                state.pc = pc + 3
                return state
            if mod == 1 and pc + 4 <= len(m):
                disp8 = _sx8(m[pc+3])
                base = _reg_name_from_low3(rm)
                addr = (_get(state, base) + disp8) & MASK64
                _write64(m, addr, _get(state, src))
                state.pc = pc + 4
                return state

        if op1 == 0x8B and pc + 3 <= len(m):
            modrm = m[pc+2]
            mod = (modrm >> 6) & 3
            reg = (modrm >> 3) & 7
            rm  = modrm & 7
            dst = _reg_name_from_low3(reg)
            if mod == 0:
                base = _reg_name_from_low3(rm)
                addr = _get(state, base)
                _set(state, dst, _read64(m, addr))
                _set(state, dst, _read64(m, addr))
                _set(state, dst, _read64(m, addr))
                state.pc = pc + 3
                return state
            if mod == 1 and pc + 4 <= len(m):
                disp8 = _sx8(m[pc+3])
                base = _reg_name_from_low3(rm)
                addr = (_get(state, base) + disp8) & MASK64
                _set(state, dst, _read64(m, addr))
                state.pc = pc + 4
                return state

        if op1 == 0x83 and pc + 4 <= len(m):
            modrm = m[pc+2]
            op = (modrm >> 3) & 7
            mod = (modrm >> 6) & 3
            rm  = modrm & 7
            if op == 7 and mod == 3:
                reg = _reg_name_from_low3(rm)
                imm8 = _sx8(m[pc+3])
                state.flags["ZF"] = ((_get(state, reg) - imm8) & MASK64) == 0
                state.pc = pc + 4
                return state

    return state
