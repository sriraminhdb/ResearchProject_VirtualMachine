from __future__ import annotations
from typing import Optional, Dict, Any, Tuple, List

from backend.backends.x86 import step as x86_step
from backend.backends.arm import step as arm_step
from backend.core.isa_detector import detect as detect_isa

from backend.core.ir import exec_ir, IROp
from backend.decoders.arm_to_ir import decode_to_ir as arm_to_ir
from backend.decoders.x86_to_ir import decode_to_ir as x86_to_ir  

def _decode_ir(mem: bytes, pc: int, isa: str) -> Tuple[List[IROp], int]:
    if isa == "arm":
        return arm_to_ir(mem, pc)
    if isa == "x86":
        return x86_to_ir(mem, pc)
    return [], 0

def dispatch(
    instr_bytes: bytes,
    state,
    isa: str,
    *,
    use_ir: bool = False,
    hooks: Optional[Dict[str, Any]] = None,
    _detect_cache: Optional[Dict[int, str]] = None,
):
    """
    One-step dispatcher.
      - isa in {'x86','arm'} => fixed backend
      - isa == 'auto'        => detect per-PC; call hooks['on_switch'] on changes
      - when use_ir=True     => try IR path first for the chosen ISA; fall back to native

    hooks:
      on_switch(prev, new, pc)
      after_decode(isa, pc, ir_type_names_list)
      after_exec(info_dict, state)
    """
    hooks = hooks or {}
    chosen = isa

    if isa == "auto":
        pc = state.pc
        prev = getattr(state, "current_isa", None)
        if _detect_cache is not None and pc in _detect_cache:
            chosen = _detect_cache[pc]
        else:
            chosen = detect_isa(instr_bytes, pc, hint=prev)
            if _detect_cache is not None:
                _detect_cache[pc] = chosen

        if prev != chosen:
            if "on_switch" in hooks:
                try:
                    hooks["on_switch"](prev, chosen, pc)
                except Exception:
                    pass
            setattr(state, "current_isa", chosen)
    else:
        setattr(state, "current_isa", isa)

    if use_ir:
        ir_ops, size = _decode_ir(instr_bytes, state.pc, chosen)

        if "after_decode" in hooks:
            try:
                hooks["after_decode"](chosen, state.pc, [type(op).__name__ for op in ir_ops])
            except Exception:
                pass

        if ir_ops:
            exec_ir(state, ir_ops)
            if "after_exec" in hooks:
                try:
                    hooks["after_exec"]({"isa": chosen}, state)
                except Exception:
                    pass
            return state

    if "after_decode" in hooks:
        try:
            hooks["after_decode"](chosen, state.pc, [])
        except Exception:
            pass

    if chosen == "arm":
        new_state = arm_step(instr_bytes, state)
    else:
        new_state = x86_step(instr_bytes, state)

    if "after_exec" in hooks:
        try:
            hooks["after_exec"]({"isa": chosen}, new_state)
        except Exception:
            pass

    return new_state
