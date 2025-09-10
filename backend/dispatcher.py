from __future__ import annotations
from typing import Any
from .backends import x86 as _x86
from .backends import arm as _arm

def dispatch(opcode: bytes, state, isa: str, *, use_ir: bool = False, use_llvm: bool = False) -> Any:
    """
    Strict single-instruction dispatch. We intentionally do not loop here;
    the orchestrator owns the stepping loop and breakpoint handling.
    """
    if isa == "x86":
        return _x86.step(state.memory, state)  # type: ignore[arg-type]
    if isa == "arm":
        return _arm.step(state.memory, state)  # type: ignore[arg-type]
    raise ValueError(f"Unknown ISA: {isa}")
