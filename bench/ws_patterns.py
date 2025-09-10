from __future__ import annotations
from typing import List
from backend.core.ir import IROp, MOV, ADD, LOAD, STORE, SUB

def make_ws_loop_ir(
    *,
    base_reg: str = "x1",
    idx_reg: str = "x2",
    tmp_reg: str = "x3",
    value_reg: str = "x4",
    start: int = 0,
    count: int = 0,
    stride: int = 1,
    mode: str = "read",
) -> List[IROp]:
    """
    Construct a tiny IR block that touches 'count' qwords from memory starting at (base + 8*start),
    stepping by 'stride'. We do NOT encode loop control with PC branches, because the bench harness
    calls this block repeatedly to amortize JIT compile time and avoid control-flow complexity.
    Side effects:
      - read: LOAD tmp <- [base + 8*start], then advance base/index
      - write: MOV value, STORE [base], then advance base/index
      - rmw: LOAD, ADD 1, STORE, then advance base/index
    """
    ops: List[IROp] = []
    ops.append(MOV(dst=idx_reg, src_reg=None, src_imm=int(start), size=1))
    ops.append(ADD(dst=base_reg, a=base_reg, b_reg=None, b_imm=int(8*start), set_flags=False, size=1))

    elem_ops: List[IROp] = []
    if mode == "read":
        elem_ops = [LOAD(dst=tmp_reg, base=base_reg, disp=0, size=1)]
    elif mode == "write":
        elem_ops = [
            MOV(dst=value_reg, src_reg=None, src_imm=0xA5A5A5A5A5A5A5A5, size=1),
            STORE(src=value_reg, base=base_reg, disp=0, size=1),
        ]
    else:  # rmw
        elem_ops = [
            LOAD(dst=tmp_reg, base=base_reg, disp=0, size=1),
            ADD(dst=tmp_reg, a=tmp_reg, b_reg=None, b_imm=1, set_flags=False, size=1),
            STORE(src=tmp_reg, base=base_reg, disp=0, size=1),
        ]

    for _ in range(int(count)):
        ops.extend(elem_ops)
        ops.append(ADD(dst=idx_reg, a=idx_reg, b_reg=None, b_imm=int(stride), set_flags=False, size=1))
        ops.append(ADD(dst=base_reg, a=base_reg, b_reg=None, b_imm=int(8*stride), set_flags=False, size=1))

    return ops
