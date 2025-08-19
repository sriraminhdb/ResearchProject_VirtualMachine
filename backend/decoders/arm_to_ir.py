from __future__ import annotations
from typing import List, Tuple
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

from backend.core.ir import IROp, NOP, MOV, ADD, SUB, CMP, JE, JMP, CBZ, LOAD, STORE

_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_md.detail = True

def _reg_name(op_or_id, insn) -> str:
    if isinstance(op_or_id, int):
        return insn.reg_name(op_or_id)
    return insn.reg_name(op_or_id.reg)

def _imm_val(op) -> int:
    return int(op.imm)

def _shift_amount(op) -> int:
    try:
        sh = getattr(op, "shift", None)
        return int(sh.value) if sh is not None else 0
    except Exception:
        return 0

def decode_to_ir(code: bytes, pc: int) -> Tuple[List[IROp], int]:
    """
    Decode a single AArch64 instruction at `pc` into a list of IR ops.
    Returns (ops, size). Branch targets are absolute.
    """
    insn = next(_md.disasm(code[pc:], pc))
    mnem = insn.mnemonic.lower()
    ops  = insn.operands
    size = insn.size
    ir: List[IROp] = []

    if mnem == "nop":
        ir.append(NOP(size=size))
        return ir, size

    if mnem == "movz" and len(ops) >= 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
        dst = _reg_name(ops[0], insn)
        imm = _imm_val(ops[1])
        sh  = _shift_amount(ops[1])
        if sh:
            imm = (imm << sh) & ((1 << 64) - 1)
        ir.append(MOV(size=size, dst=dst, src_imm=imm))
        return ir, size

    if mnem == "mov" and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
        dst = _reg_name(ops[0], insn)
        if ops[1].type == ARM64_OP_IMM:
            ir.append(MOV(size=size, dst=dst, src_imm=_imm_val(ops[1])))
        elif ops[1].type == ARM64_OP_REG:
            ir.append(MOV(size=size, dst=dst, src_reg=_reg_name(ops[1], insn)))
        else:
            pass
        return ir, size

    if mnem in ("add", "adds") and len(ops) >= 3 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
        dst  = _reg_name(ops[0], insn)
        a    = _reg_name(ops[1], insn)
        setf = (mnem == "adds")
        if ops[2].type == ARM64_OP_IMM:
            ir.append(ADD(size=size, dst=dst, a=a, b_imm=_imm_val(ops[2]), set_flags=setf))
        elif ops[2].type == ARM64_OP_REG:
            ir.append(ADD(size=size, dst=dst, a=a, b_reg=_reg_name(ops[2], insn), set_flags=setf))
        else:
            ir.append(ADD(size=size, dst=dst, a=a, b_imm=0, set_flags=setf))
        return ir, size

    if mnem in ("sub", "subs") and len(ops) >= 3 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
        dst  = _reg_name(ops[0], insn)
        a    = _reg_name(ops[1], insn)
        setf = (mnem == "subs")
        if ops[2].type == ARM64_OP_IMM:
            ir.append(SUB(size=size, dst=dst, a=a, b_imm=_imm_val(ops[2]), set_flags=setf))
        elif ops[2].type == ARM64_OP_REG:
            ir.append(SUB(size=size, dst=dst, a=a, b_reg=_reg_name(ops[2], insn), set_flags=setf))
        else:
            ir.append(SUB(size=size, dst=dst, a=a, b_imm=0, set_flags=setf))
        return ir, size

    if mnem == "cmp" and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        a = _reg_name(ops[0], insn)
        if ops[1].type == ARM64_OP_IMM:
            ir.append(CMP(size=size, a_reg=a, b_imm=_imm_val(ops[1])))
        elif ops[1].type == ARM64_OP_REG:
            ir.append(CMP(size=size, a_reg=a, b_reg=_reg_name(ops[1], insn)))
        else:
            ir.append(CMP(size=size, a_reg=a, b_imm=0))
        return ir, size

    if mnem == "cbz" and len(ops) >= 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
        reg    = _reg_name(ops[0], insn)
        target = int(_imm_val(ops[1]))  
        ir.append(CBZ(size=size, reg=reg, target=target))
        return ir, size

    if mnem == "b" and len(ops) == 1 and ops[0].type == ARM64_OP_IMM:
        target = int(_imm_val(ops[0]))
        ir.append(JMP(size=size, target=target))
        return ir, size

    if mnem == "ldr" and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM:
        base = _reg_name(ops[1].mem.base, insn)
        disp = int(ops[1].mem.disp)
        dst  = _reg_name(ops[0], insn)
        ir.append(LOAD(size=size, dst=dst, base=base, disp=disp))
        return ir, size

    if mnem == "str" and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM:
        base = _reg_name(ops[1].mem.base, insn)
        disp = int(ops[1].mem.disp)
        src  = _reg_name(ops[0], insn)
        ir.append(STORE(size=size, src=src, base=base, disp=disp))
        return ir, size

    return [], size
