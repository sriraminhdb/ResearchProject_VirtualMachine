from __future__ import annotations
from typing import Optional, Union
from struct import pack, unpack_from
from backend.core.ir import *

MASK64 = (1 << 64) - 1

def _get(state, regname: str) -> int:
    return int(state.registers.get(regname, 0)) & MASK64

def _set(state, regname: str, val: int) -> None:
    state.registers[regname] = int(val) & MASK64

def _ensure(mem: bytearray, length: int) -> None:
    if length < 0:
        return
    if length > len(mem):
        mem.extend(b"\x00" * (length - len(mem)))

def _val(state, x: Union[Reg, Imm]) -> int:
    return _get(state, x.name) if isinstance(x, Reg) else int(x.val)

def _addr(state, m: Mem) -> int:
    base = _get(state, m.base)
    idx  = _get(state, m.index) if m.index else 0
    return (base + idx * (m.scale or 1) + int(m.disp)) & MASK64

def execute(ir_ops: list, state) -> Optional[int]:
    """
    Execute a linear IR block.
    Return an override PC (int) if control flow changed, else None.
    """
    pc_override: Optional[int] = None

    for op in ir_ops:
        if isinstance(op, NOP):
            pass

        elif isinstance(op, LEA):
            a = _addr(state, op.addr)
            _set(state, op.dst.name, a)

        elif isinstance(op, MOV):
            _set(state, op.dst.name, _val(state, op.src))

        elif isinstance(op, LOAD):
            addr = _addr(state, op.addr)
            width = op.addr.width or 8
            _ensure(state.memory, addr + width)
            if width == 8:
                v = unpack_from("<Q", state.memory, addr)[0]
            elif width == 4:
                v = unpack_from("<I", state.memory, addr)[0]
            elif width == 2:
                v = unpack_from("<H", state.memory, addr)[0]
            else:
                v = state.memory[addr]
            _set(state, op.dst.name, v)

        elif isinstance(op, STORE):
            addr = _addr(state, op.addr)
            width = op.addr.width or 8
            val = _val(state, op.src) & MASK64
            _ensure(state.memory, addr + width)
            if width == 8:
                state.memory[addr:addr+8] = pack("<Q", val)
            elif width == 4:
                state.memory[addr:addr+4] = pack("<I", val & 0xFFFFFFFF)
            elif width == 2:
                state.memory[addr:addr+2] = pack("<H", val & 0xFFFF)
            else:
                state.memory[addr:addr+1] = bytes([val & 0xFF])

        elif isinstance(op, ADD):
            _set(state, op.dst.name, (_val(state, op.a) + _val(state, op.b)) & MASK64)

        elif isinstance(op, SUB):
            _set(state, op.dst.name, (_val(state, op.a) - _val(state, op.b)) & MASK64)

        elif isinstance(op, CMP_EQ):
            state.flags["ZF"] = (_val(state, op.a) - _val(state, op.b)) == 0

        elif isinstance(op, BR_IF):
            if state.flags.get(op.flag, False):
                pc_override = int(op.taken) & MASK64
            else:
                pc_override = int(op.fallthrough) & MASK64
            break

        elif isinstance(op, JMP):
            tgt = op.target if isinstance(op.target, int) else _get(state, op.target.name)
            pc_override = int(tgt) & MASK64
            break

        elif isinstance(op, CALL):
            rsp = state.registers.get("rsp", state.registers.get("sp", 0))
            rsp -= 8
            _ensure(state.memory, rsp + 8)
            state.memory[rsp:rsp+8] = pack("<Q", int(op.retaddr) & MASK64)
            state.registers["rsp"] = rsp 
            pc_override = int(op.target) & MASK64
            break

        elif isinstance(op, RET):
            rsp = state.registers.get("rsp", state.registers.get("sp", 0))
            _ensure(state.memory, rsp + 8)
            ret = unpack_from("<Q", state.memory, rsp)[0]
            state.registers["rsp"] = rsp + 8 + (int(op.imm) & 0xFFFF)
            pc_override = ret & MASK64
            break

        else:
            pass

    return pc_override
