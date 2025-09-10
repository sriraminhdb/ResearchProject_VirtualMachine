from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from .. import ir as I

_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_md.detail = True

def _r(insn, op): return I.Reg(insn.reg_name(op.reg))
def _imm(v): return I.Imm(int(v))

def _mem(insn, op, width=8):
    m = op.mem
    base = insn.reg_name(m.base) if m.base != 0 else None
    return I.Mem(base=base, index=None, scale=1, disp=m.disp, width=width)

def decode_one(memory: bytes, pc: int):
    insn = next(_md.disasm(memory[pc:], pc))
    m, ops = insn.mnemonic, insn.operands
    ir = []
    nxt = insn.address + insn.size

    if m == "nop":
        return insn.size, [I.NOP()]

    if m == "b" and len(ops) == 1 and ops[0].type == ARM64_OP_IMM:
        return insn.size, [I.JMP(ops[0].imm)]

    if m == "cbz" and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
        return insn.size, [I.BR_ZERO(_r(insn, ops[0]), ops[1].imm)]

    if m == "bl" and ops[0].type == ARM64_OP_IMM:
        ir += [I.MOV(I.Reg("x30"), I.Imm(nxt)), I.CALL(ops[0].imm)]
        return insn.size, ir

    if m == "ret":
        return insn.size, [I.NOP()]

    if m.startswith("mov") and ops[0].type == ARM64_OP_REG:
        d = _r(insn, ops[0])
        s = (_r(insn, ops[1]) if ops[1].type == ARM64_OP_REG else _imm(ops[1].imm))
        ir.append(I.MOV(d, s)); return insn.size, ir

    if m == "add" and ops[0].type == ARM64_OP_REG:
        d = _r(insn, ops[0])
        a = _r(insn, ops[1]) if ops[1].type == ARM64_OP_REG else _imm(ops[1].imm)
        b = _r(insn, ops[2]) if ops[2].type == ARM64_OP_REG else _imm(ops[2].imm)
        ir.append(I.ADD(d, a, b)); return insn.size, ir

    if m in ("cmp","subs") and ops[0].type == ARM64_OP_REG:
        a = _r(insn, ops[0])
        b = _r(insn, ops[1]) if ops[1].type == ARM64_OP_REG else _imm(ops[1].imm)
        ir.append(I.CMP(a, b)); return insn.size, ir

    if m == "ldr" and ops[1].type == ARM64_OP_MEM:
        d = _r(insn, ops[0]); ir.append(I.LOAD(d, _mem(insn, ops[1], 8))); return insn.size, ir
    if m == "str" and ops[1].type == ARM64_OP_MEM:
        s = _r(insn, ops[0]); ir.append(I.STORE(s, _mem(insn, ops[1], 8))); return insn.size, ir

    return insn.size, [I.NOP()]
