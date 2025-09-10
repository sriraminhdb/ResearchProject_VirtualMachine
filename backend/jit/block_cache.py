from __future__ import annotations
from typing import Dict, Tuple, List
from backend.core.ir import IROp, exec_ir

try:
    from backend.jit.engine import compile_block
except Exception:
    compile_block = None

_CACHE: Dict[Tuple[str, int, Tuple[int, ...]], object] = {}

def _key(isa: str, pc: int, ir_ops: List[IROp]) -> Tuple[str, int, Tuple[int, ...]]:
    sig = tuple((hash(type(op).__name__) ^ op.size) for op in ir_ops)
    return (isa, pc, sig)

def execute_with_cache(isa: str, pc: int, ir_ops: List[IROp], state):
    if not ir_ops:
        return False
    k = _key(isa, pc, ir_ops)
    fn = _CACHE.get(k)
    if fn is None:
        if compile_block is None:
            def _interp(s): exec_ir(s, ir_ops)
            fn = _interp
        else:
            fn = compile_block(ir_ops)
        _CACHE[k] = fn
    fn(state)
    return True
