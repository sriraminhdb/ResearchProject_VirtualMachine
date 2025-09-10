from struct import pack, unpack_from
from typing import Dict, Callable, Optional
from .ir import *

MASK64 = (1 << 64) - 1

def _ens(mem: bytearray, need_len: int) -> None:
    if need_len < 0:
        raise ValueError("negative memory length requested")
    if need_len > len(mem):
        mem.extend(b"\x00" * (need_len - len(mem)))

def _val(state, op: Op) -> int:
    if isinstance(op, Imm): return op.value & MASK64
    if isinstance(op, Reg): return state.registers.get(op.name, 0) & MASK64
    if isinstance(op, Mem):
        addr = 0
        if op.base:  addr += state.registers.get(op.base, 0)
        if op.index: addr += state.registers.get(op.index, 0) * (op.scale or 1)
        addr += op.disp
        _ens(state.memory, addr + op.width)
        if op.width == 8:
            return unpack_from("<Q", state.memory, addr)[0]
        elif op.width == 4:
            return unpack_from("<I", state.memory, addr)[0]
        elif op.width == 1:
            return state.memory[addr]
        else:
            raise NotImplementedError("unsupported width")
    return 0

def _store(state, addr: Mem, v: int) -> None:
    a = 0
    if addr.base:  a += state.registers.get(addr.base, 0)
    if addr.index: a += state.registers.get(addr.index, 0) * (addr.scale or 1)
    a += addr.disp
    _ens(state.memory, a + addr.width)
    if addr.width == 8:
        state.memory[a:a+8] = pack("<Q", v & MASK64)
    elif addr.width == 4:
        state.memory[a:a+4] = pack("<I", v & 0xFFFFFFFF)
    elif addr.width == 1:
        state.memory[a] = v & 0xFF
    else:
        raise NotImplementedError("unsupported width")

def exec_ir(ir: IRList, state, hooks: Optional[Dict[str, Callable]] = None) -> None:
    """
    Execute a single machine-instruction worth of IR.
    Updates state.pc when control-flow ops occur; sets ZF for CMP/XOR.
    """
    hooks = hooks or {}
    before = hooks.get("before_exec", lambda *a, **k: None)
    after  = hooks.get("after_exec",  lambda *a, **k: None)

    for op in ir:
        before(op)
        if isinstance(op, NOP):
            after("NOP", state); continue

        if isinstance(op, MOV):
            v = _val(state, op.src)
            state.registers[op.dst.name] = v & MASK64
            after("MOV", state); continue

        if isinstance(op, LEA):
            v = _val(state, op.addr)
            state.registers[op.dst.name] = v & MASK64
            after("LEA", state); continue

        if isinstance(op, LOAD):
            state.registers[op.dst.name] = _val(state, op.addr) & MASK64
            after("LOAD", state); continue

        if isinstance(op, STORE):
            _store(state, op.addr, _val(state, op.src))
            after("STORE", state); continue

        if isinstance(op, ADD):
            r = (_val(state, op.a) + _val(state, op.b)) & MASK64
            state.registers[op.dst.name] = r
            after("ADD", state); continue

        if isinstance(op, SUB):
            r = (_val(state, op.a) - _val(state, op.b)) & MASK64
            state.registers[op.dst.name] = r
            after("SUB", state); continue

        if isinstance(op, XOR):
            r = (_val(state, op.a) ^ _val(state, op.b)) & MASK64
            state.registers[op.dst.name] = r
            state.flags["ZF"] = (r == 0)
            after("XOR", state); continue

        if isinstance(op, CMP):
            state.flags["ZF"] = (_val(state, op.a) - _val(state, op.b)) % (1<<64) == 0
            after("CMP", state); continue

        if isinstance(op, JMP):
            state.pc = op.target
            after("JMP", state); return

        if isinstance(op, JE):
            if state.flags.get("ZF", False):
                state.pc = op.target
                after("JE", state); return
            after("JE(nottaken)", state); continue

        if isinstance(op, CALL):
            ret = state.pc
            sp_name = "rsp" if "rsp" in state.registers else "sp"
            state.registers[sp_name] -= 8
            _ens(state.memory, state.registers[sp_name] + 8)
            state.memory[state.registers[sp_name]:state.registers[sp_name]+8] = pack("<Q", ret)
            state.pc = op.target
            after("CALL", state); return

        if isinstance(op, RET):
            sp_name = "rsp" if "rsp" in state.registers else "sp"
            sp = state.registers.get(sp_name, 0)
            if sp + 8 <= len(state.memory):
                ret_addr = unpack_from("<Q", state.memory, sp)[0]
                state.registers[sp_name] = sp + 8 + (op.pop_bytes & 0xFFFF)
                state.pc = ret_addr
            after("RET", state); return

        if isinstance(op, BR_ZERO):
            r = state.registers.get(op.reg.name, 0)
            if r == 0:
                state.pc = op.target
                after("BR_ZERO", state); return
            after("BR_ZERO(nottaken)", state); continue
