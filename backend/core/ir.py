from __future__ import annotations
from typing import List, Optional
from struct import pack, unpack_from

from backend.backends.x86 import _ensure

class IROp:
    """Base IR op. `size` is the source-instruction byte length."""
    def __init__(self, size: int) -> None:
        self.size = size

class NOP(IROp):
    pass

class MOV(IROp):
    def __init__(self, *, size: int, dst: str,
                 src_reg: Optional[str] = None,
                 src_imm: Optional[int] = None) -> None:
        super().__init__(size)
        self.dst = dst
        self.src_reg = src_reg
        self.src_imm = src_imm

class ADD(IROp):
    def __init__(self, *, size: int, dst: str, a: str,
                 b_reg: Optional[str] = None,
                 b_imm: Optional[int] = None,
                 b_shift: int = 0,
                 set_flags: bool = False) -> None:
        super().__init__(size)
        self.dst = dst
        self.a = a
        self.b_reg = b_reg
        self.b_imm = b_imm
        self.b_shift = b_shift
        self.set_flags = set_flags

class SUB(IROp):
    def __init__(self, *, size: int, dst: str, a: str,
                 b_reg: Optional[str] = None,
                 b_imm: Optional[int] = None,
                 b_shift: int = 0,
                 set_flags: bool = False) -> None:
        super().__init__(size)
        self.dst = dst
        self.a = a
        self.b_reg = b_reg
        self.b_imm = b_imm
        self.b_shift = b_shift
        self.set_flags = set_flags

class AND(IROp):
    def __init__(self, *, size:int, dst:str, a:str,
                 b_reg:Optional[str]=None, b_imm:Optional[int]=None,
                 b_shift:int = 0,
                 set_flags: bool = False) -> None:
        super().__init__(size)
        self.dst, self.a = dst, a
        self.b_reg, self.b_imm, self.b_shift = b_reg, b_imm, b_shift
        self.set_flags = set_flags

class OR(IROp):
    def __init__(self, *, size:int, dst:str, a:str,
                 b_reg:Optional[str]=None, b_imm:Optional[int]=None,
                 b_shift:int = 0,
                 set_flags: bool = False) -> None:
        super().__init__(size)
        self.dst, self.a = dst, a
        self.b_reg, self.b_imm, self.b_shift = b_reg, b_imm, b_shift
        self.set_flags = set_flags

class XOR(IROp):
    def __init__(self, *, size:int, dst:str, a:str,
                 b_reg:Optional[str]=None, b_imm:Optional[int]=None,
                 b_shift:int = 0,
                 set_flags: bool = False) -> None:
        super().__init__(size)
        self.dst, self.a = dst, a
        self.b_reg, self.b_imm, self.b_shift = b_reg, b_imm, b_shift
        self.set_flags = set_flags

class CMP(IROp):
    def __init__(self, *, size: int, a_reg: str,
                 b_reg: Optional[str] = None,
                 b_imm: Optional[int] = None) -> None:
        super().__init__(size)
        self.a_reg = a_reg
        self.b_reg = b_reg
        self.b_imm = b_imm

class JE(IROp):
    def __init__(self, *, size: int, target: int) -> None:
        super().__init__(size)
        self.target = target

class JMP(IROp):
    def __init__(self, *, size: int, target: int) -> None:
        super().__init__(size)
        self.target = target

class CBZ(IROp):
    def __init__(self, *, size: int, reg: str, target: int) -> None:
        super().__init__(size)
        self.reg = reg
        self.target = target

class LOAD(IROp):
    def __init__(self, *, size: int, dst: str, base: str, disp: int) -> None:
        super().__init__(size)
        self.dst = dst
        self.base = base
        self.disp = disp

class STORE(IROp):
    def __init__(self, *, size: int, src: str, base: str, disp: int) -> None:
        super().__init__(size)
        self.src = src
        self.base = base
        self.disp = disp

class MOVK(IROp):
    def __init__(self, *, size:int, dst:str, imm16:int, shift:int) -> None:
        super().__init__(size)
        self.dst, self.imm16, self.shift = dst, imm16 & 0xFFFF, shift

def _u64(x: int) -> int:
    return x & ((1 << 64) - 1)

def exec_ir(state, ops: List[IROp]) -> None:
    """
    Execute a small list of IR ops against the given VMState in-place.
    """
    mem = state.memory  # bytearray

    def getr(r: str) -> int:
        return int(state.registers.get(r, 0))

    def setr(r: str, v: int) -> None:
        state.registers[r] = _u64(v)

    def ensure_mem(nbytes: int) -> None:
        if nbytes < 0:
            return
        if nbytes > len(mem):
            mem.extend(b"\x00" * (nbytes - len(mem)))

    def read_q(addr: int) -> int:
        ensure_mem(addr + 8)
        return int.from_bytes(mem[addr:addr+8], "little", signed=False)

    def write_q(addr: int, v: int) -> None:
        ensure_mem(addr + 8)
        mem[addr:addr+8] = int(_u64(v)).to_bytes(8, "little", signed=False)

    def _read64(state, addr):
        _ensure(state.memory, addr + 8)
        return unpack_from("<Q", state.memory, addr)[0]

    def _write64(state, addr, val):
        _ensure(state.memory, addr + 8)
        state.memory[addr:addr+8] = pack("<Q", val & ((1<<64)-1))

    for op in ops:
        if isinstance(op, NOP):
            state.pc += op.size

        elif isinstance(op, MOV):
            if op.src_reg is not None:
                setr(op.dst, getr(op.src_reg))
            else:
                setr(op.dst, int(op.src_imm or 0))
            state.pc += op.size

        elif isinstance(op, ADD):
            b = getr(op.b_reg) if op.b_reg is not None else int(op.b_imm or 0)
            if op.b_reg is not None and op.b_shift:
                b = _u64(b) << op.b_shift
            res = getr(op.a) + b
            setr(op.dst, res)
            if op.set_flags:
                state.flags["ZF"] = (_u64(res) == 0)
            state.pc += op.size

        elif isinstance(op, SUB):
            b = getr(op.b_reg) if op.b_reg is not None else int(op.b_imm or 0)
            if op.b_reg is not None and op.b_shift:
                b = _u64(b) << op.b_shift
            res = getr(op.a) - b
            setr(op.dst, res)
            if op.set_flags:
                state.flags["ZF"] = (_u64(res) == 0)
            state.pc += op.size

        elif isinstance(op, AND):
            b = getr(op.b_reg) if op.b_reg is not None else int(op.b_imm or 0)
            if op.b_reg is not None and op.b_shift:
                b = _u64(b) << op.b_shift
            res = getr(op.a) & b
            setr(op.dst, res)
            if op.set_flags:
                state.flags["ZF"] = (_u64(res) == 0)
            state.pc += op.size

        elif isinstance(op, OR):
            b = getr(op.b_reg) if op.b_reg is not None else int(op.b_imm or 0)
            if op.b_reg is not None and op.b_shift:
                b = _u64(b) << op.b_shift
            res = getr(op.a) | b
            setr(op.dst, res)
            if op.set_flags:
                state.flags["ZF"] = (_u64(res) == 0)
            state.pc += op.size

        elif isinstance(op, XOR):
            b = getr(op.b_reg) if op.b_reg is not None else int(op.b_imm or 0)
            if op.b_reg is not None and op.b_shift:
                b = _u64(b) << op.b_shift
            res = getr(op.a) ^ b
            setr(op.dst, res)
            if op.set_flags:
                state.flags["ZF"] = (_u64(res) == 0)
            state.pc += op.size

        elif isinstance(op, CMP):
            b = getr(op.b_reg) if op.b_reg is not None else int(op.b_imm or 0)
            res = getr(op.a_reg) - b
            state.flags["ZF"] = (_u64(res) == 0)
            state.pc += op.size

        elif isinstance(op, JE):
            if state.flags.get("ZF", False):
                state.pc = op.target
            else:
                state.pc += op.size

        elif isinstance(op, JMP):
            state.pc = op.target

        elif isinstance(op, CBZ):
            if getr(op.reg) == 0:
                state.pc = op.target
            else:
                state.pc += op.size

        elif isinstance(op, LOAD):
            addr = (state.registers.get(op.base, 0) + op.disp) & ((1<<64)-1)
            state.registers[op.dst] = _read64(state, addr)
            state.pc += op.size

        elif isinstance(op, STORE):
            addr = (state.registers.get(op.base, 0) + op.disp) & ((1<<64)-1)
            _write64(state, addr, state.registers.get(op.src, 0))
            state.pc += op.size

        elif isinstance(op, MOVK):
            old = getr(op.dst)
            mask = ~(0xFFFF << op.shift) & ((1<<64)-1)
            newv = (old & mask) | ((op.imm16 & 0xFFFF) << op.shift)
            setr(op.dst, newv)
            state.pc += op.size

        else:
            state.pc += getattr(op, "size", 1)


__all__ = [
    "IROp", "exec_ir",
    "NOP", "MOV", "ADD", "SUB", "CMP", "JE", "JMP", "CBZ",
    "LOAD", "STORE", "AND", "OR", "XOR", "MOVK",
]
