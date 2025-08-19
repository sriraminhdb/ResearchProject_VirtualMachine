from __future__ import annotations
from dataclasses import dataclass
from typing import List, Union

U64 = (1 << 64) - 1

@dataclass
class IRNop:           pass

@dataclass
class IRMovImm:
    dst: str
    imm: int

@dataclass
class IRMovReg:
    dst: str
    src: str

@dataclass
class IRAdd:
    dst: str
    a:   str
    b:   Union[str, int]  

@dataclass
class IRSub:
    dst: str
    a:   str
    b:   Union[str, int]   

@dataclass
class IRLoad:          
    dst:   str
    base:  str
    disp:  int = 0
    index: str | None = None
    scale: int = 1

@dataclass
class IRStore:         
    src:   str
    base:  str
    disp:  int = 0
    index: str | None = None
    scale: int = 1

@dataclass
class IRCmp:           
    a: Union[str, int]
    b: Union[str, int]

@dataclass
class IRJmp:           
    target: int

@dataclass
class IRJe:            
    target: int

@dataclass
class IRLea:          
    dst:   str
    base:  str | None = None
    disp:  int = 0
    index: str | None = None
    scale: int = 1

@dataclass
class IRXor:          
    dst: str
    a:   str
    b:   str

def _canon64(n: str) -> str:
    n = n.lower()
    m32 = {"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx","esi":"rsi","edi":"rdi","esp":"rsp","ebp":"rbp"}
    m16 = {"ax":"rax","bx":"rbx","cx":"rcx","dx":"rdx","si":"rsi","di":"rdi","sp":"rsp","bp":"rbp"}
    m8  = {"al":"rax","bl":"rbx","cl":"rcx","dl":"rdx","ah":"rax","bh":"rbx","ch":"rcx","dh":"rdx",
           "sil":"rsi","dil":"rdi","spl":"rsp","bpl":"rbp"}
    if n in m32: return m32[n]
    if n in m16: return m16[n]
    if n in m8 : return m8[n]
    if len(n)>=3 and n[0]=="r" and n[-1] in "dwb":
        base=n[:-1]
        try:
            i=int(base[1:])
            if 8<=i<=15: return base
        except: pass
    return n

def _get(st, reg): return st.registers.get(_canon64(reg), 0)
def _set(st, reg, val): st.registers[_canon64(reg)] = val & U64

def _ensure(mem, length):
    if length < 0: return
    if length > len(mem):
        mem.extend(b"\x00" * (length - len(mem)))

def _addr(st, base, disp, index, scale):
    addr = 0
    if base:  addr += _get(st, base)
    if index: addr += _get(st, index) * (scale or 1)
    addr += disp
    return addr

def exec_ops(ops: List[object], state) -> bool:
    """
    Execute the IR list; return True if a control transfer changed PC,
    so the caller should NOT auto-advance by insn.size.
    """
    branched = False
    for op in ops:
        if isinstance(op, IRNop):
            pass

        elif isinstance(op, IRMovImm):
            _set(state, op.dst, op.imm)

        elif isinstance(op, IRMovReg):
            _set(state, op.dst, _get(state, op.src))

        elif isinstance(op, IRAdd):
            rhs = _get(state, op.b) if isinstance(op.b, str) else int(op.b)
            _set(state, op.dst, (_get(state, op.a) + rhs) & U64)

        elif isinstance(op, IRSub):
            rhs = _get(state, op.b) if isinstance(op.b, str) else int(op.b)
            _set(state, op.dst, (_get(state, op.a) - rhs) & U64)

        elif isinstance(op, IRLoad):
            addr = _addr(state, op.base, op.disp, op.index, op.scale)
            _ensure(state.memory, addr + 8)
            from struct import unpack_from
            _set(state, op.dst, unpack_from("<Q", state.memory, addr)[0])

        elif isinstance(op, IRStore):
            addr = _addr(state, op.base, op.disp, op.index, op.scale)
            _ensure(state.memory, addr + 8)
            from struct import pack
            state.memory[addr:addr+8] = pack("<Q", _get(state, op.src))

        elif isinstance(op, IRCmp):
            a = _get(state, op.a) if isinstance(op.a, str) else int(op.a)
            b = _get(state, op.b) if isinstance(op.b, str) else int(op.b)
            state.flags["ZF"] = (a - b) == 0

        elif isinstance(op, IRJmp):
            state.pc = op.target
            branched = True

        elif isinstance(op, IRJe):
            if state.flags.get("ZF", False):
                state.pc = op.target
                branched = True

        elif isinstance(op, IRLea):
            addr = _addr(state, op.base, op.disp, op.index, op.scale)
            _set(state, op.dst, addr & U64)

        elif isinstance(op, IRXor):
            val = _get(state, op.a) ^ _get(state, op.b)
            _set(state, op.dst, val)
            state.flags["ZF"] = (val == 0)

        else:
            pass
    return branched
