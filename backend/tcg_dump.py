from __future__ import annotations
from typing import List
from backend.core.ir import IROp, NOP, MOV, ADD, SUB, CMP, JE, JMP, CBZ, LOAD, STORE

def _sym(x):
    return str(x)

def render_tcg(ir_ops: List[IROp], *, pc: int) -> List[str]:
    """
    Return a TCG-flavoured textual dump for the given IR ops.
    This is not executable TCG, but mirrors tcg_gen_* call shapes.
    """
    out: List[str] = [f"# TCG block @0x{pc:x}  (from {len(ir_ops)} IR ops)"]
    tcount = 0
    def tmp():
        nonlocal tcount
        t = f"t{tcount}"
        tcount += 1
        return t

    for op in ir_ops:
        if isinstance(op, NOP):
            out.append("  # nop")

        elif isinstance(op, MOV):
            if op.src_reg is not None:
                out.append(f"  tcg_gen_mov_i64({_sym(op.dst)}, {_sym(op.src_reg)})")
            else:
                out.append(f"  tcg_gen_movi_i64({_sym(op.dst)}, {int(op.src_imm or 0)})")

        elif isinstance(op, ADD):
            if op.b_reg is not None:
                out.append(f"  tcg_gen_add_i64({_sym(op.dst)}, {_sym(op.a)}, {_sym(op.b_reg)})")
            else:
                out.append(f"  tcg_gen_addi_i64({_sym(op.dst)}, {_sym(op.a)}, {int(op.b_imm or 0)})")
            if op.set_flags:
                t = tmp()
                out.append(f"  {t} = {_sym(op.dst)};  # ZF <- ({t}==0)")

        elif isinstance(op, SUB):
            if op.b_reg is not None:
                out.append(f"  tcg_gen_sub_i64({_sym(op.dst)}, {_sym(op.a)}, {_sym(op.b_reg)})")
            else:
                out.append(f"  tcg_gen_subi_i64({_sym(op.dst)}, {_sym(op.a)}, {int(op.b_imm or 0)})")
            if op.set_flags:
                t = tmp()
                out.append(f"  {t} = {_sym(op.dst)};  # ZF <- ({t}==0)")

        elif isinstance(op, CMP):
            t = tmp()
            if op.b_reg is not None:
                out.append(f"  tcg_gen_sub_i64({t}, {_sym(op.a_reg)}, {_sym(op.b_reg)})")
            else:
                out.append(f"  tcg_gen_subi_i64({t}, {_sym(op.a_reg)}, {int(op.b_imm or 0)})")
            out.append(f"  # setcond EQ -> ZF from ({t}==0)")

        elif isinstance(op, JE):
            out.append(f"  # if (ZF) goto 0x{op.target:x}")
            out.append(f"  tcg_gen_brcondi_i32(TCG_COND_NE, ZF, 0, .+{op.size})  # fall-through if !ZF")
            out.append(f"  tcg_gen_goto_tb(0, 0x{op.target:x})")

        elif isinstance(op, JMP):
            out.append(f"  tcg_gen_goto_tb(0, 0x{op.target:x})")

        elif isinstance(op, CBZ):
            out.append(f"  tcg_gen_brcondi_i64(TCG_COND_EQ, {_sym(op.reg)}, 0, 0x{op.target:x})")

        elif isinstance(op, LOAD):
            addr = tmp()
            out.append(f"  tcg_gen_addi_i64({addr}, {_sym(op.base)}, {op.disp})")
            out.append(f"  tcg_gen_qemu_ld_i64({_sym(op.dst)}, {addr}, MO_64)")

        elif isinstance(op, STORE):
            addr = tmp()
            out.append(f"  tcg_gen_addi_i64({addr}, {_sym(op.base)}, {op.disp})")
            out.append(f"  tcg_gen_qemu_st_i64({_sym(op.src)}, {addr}, MO_64)")

        else:
            out.append(f"  # (unmapped IR: {type(op).__name__})")

    return out