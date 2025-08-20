from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Set, Callable, Dict, Any

STACK_SIZE = 4096

@dataclass
class VMState:
    memory: bytearray
    registers: dict
    pc: int
    flags: dict
    code_end: int
    current_isa: Optional[str] = None

    def __init__(self, memory: bytes, registers=None, pc: int = 0):
        self.memory = bytearray(memory)
        self.code_end = len(self.memory)
        self.memory.extend(b"\x00" * STACK_SIZE)

        self.registers = dict(registers or {})
        self.pc = pc
        self.flags = {"ZF": False, "_depth": 0, "_halt": False}

        top = len(self.memory)
        self.registers.setdefault("rsp", top)
        self.registers.setdefault("sp", top)

def run_bytes(
    memory: bytes,
    isa: str,
    *,
    max_steps: int = 100_000,
    breakpoints: Optional[Set[int]] = None,
    trace: Optional[Callable[[str, dict], None]] = None,
    use_ir: bool = False,
    use_jit: bool = False,
    registers: Optional[Dict[str, int]] = None,
) -> VMState:
    """
    If isa in {'x86','arm'} and use_ir=False → legacy per-ISA step path.
    If isa == 'auto' or use_ir=True → dispatcher still routes per-insn, but
    may choose the common IR on a per-instruction basis.
    """
    from backend.dispatcher import dispatch

    bp = set(breakpoints or [])
    state = VMState(memory=bytearray(memory), registers=registers or {}, pc=0)
    steps = 0
    same_pc_count = 0
    _top = len(state.memory)
    _stack_touched = False

    hooks: Dict[str, Any] = {}
    if trace:
        hooks["after_decode"] = lambda chosen, pc, ir: trace("after_decode", {"isa": chosen, "pc": pc, "ir": [*ir]})
        hooks["before_exec"] = lambda op: trace("before_exec", {"op": type(op).__name__})
        hooks["after_exec"] = lambda info, st: trace("after_exec", {"op": info, "pc": st.pc})
        hooks["on_switch"] = lambda old, new, pc: trace("on_switch", {"from": old, "to": new, "pc": pc})

    detect_cache: Dict[int, str] = {}

    initial_rsp = len(state.memory)
    initial_sp = initial_rsp

    state.registers.setdefault("rsp", initial_rsp)  
    state.registers.setdefault("sp", initial_sp)   

    while 0 <= state.pc < state.code_end and not state.flags.get("_halt", False):
        if state.pc in bp:
            state.flags["_halt"] = True
            break

        pc_before = state.pc
        state = dispatch(state.memory, state, isa, use_ir=use_ir, use_jit=use_jit, hooks=hooks, _detect_cache=detect_cache)
        steps += 1
        state.flags["_steps"] = steps

        if (state.registers.get("rsp", _top) != _top) or \
           (state.registers.get("sp", _top)  != _top):
            _stack_touched = True

        if steps >= max_steps:
            state.flags["_halt"] = True
            break

        if state.pc == pc_before:
            same_pc_count += 1
            if same_pc_count >= 2:
                state.flags["_halt"] = True
                break
        else:
            same_pc_count = 0

    if (not _stack_touched and
        state.registers.get("rsp") == _top and
        state.registers.get("sp")  == _top):
        state.registers.pop("rsp", None)
        state.registers.pop("sp", None)

    return state
