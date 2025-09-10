from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
from .. import ir as I

_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True

def _canon64(n: str) -> str:
    n = n.lower()
    maps = {
        "eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx",
        "esi":"rsi","edi":"rdi","esp":"rsp","ebp":"rbp",
        "ax":"rax","bx":"rbx","cx":"rcx","dx":"rdx",
        "si":"rsi","di":"rdi","sp":"rsp","bp":"rbp",
        "al":"rax","bl":"rbx","cl":"rcx","dl":"rdx",
        "ah":"rax","bh":"rbx","ch":"rcx","dh":"rdx",
        "sil":"rsi","dil":"rdi","spl":"rsp","bpl":"rbp",
    }
    if n in maps: return maps[n]
    if len(n) >= 3 and n[0] == "r" and n[-1] in "dwb":
        return n[:-1] 
    return n

def _reg(op, insn): return I.Reg(_canon64(insn.reg_name(op.reg)))
def _imm(v): return I.Imm(int(v))

def _mem(op, insn, width=8):
    m = op.mem
    base  = insn.reg_name(m.base) if m.base != 0 else None
    index = insn.reg_name(m.index) if m.index != 0 else None
    return I.Mem(
        base=_canon64(base) if base else None,
        index=_canon64(index) if index else None,
        scale=m.scale or 1,
        disp=m.disp,
        width=width
    )

def decode_one(memory: bytes, pc: int):
    insn = next(_md.disasm(memory[pc:], pc))
    m, ops = insn.mnemonic, insn.operands
    ir = []

    def next_pc(): return insn.address + insn.size

    if m == "nop": return insn.size, [I.NOP()]

    if m == "lea" and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
        ir.append(I.LEA(_reg(ops[0], insn), _mem(ops[1], insn)))
        return insn.size, ir

    if m == "xor" and ops[0].type == X86_OP_REG and ops[1].type in (X86_OP_REG, X86_OP_IMM):
        a = _reg(ops[0], insn)
        b = _reg(ops[1], insn) if ops[1].type == X86_OP_REG else _imm(ops[1].imm)
        ir.append(I.XOR(a, a, b))
        return insn.size, ir

    if m in ("mov", "movabs"):
        dst, src = ops[0], ops[1]
        if dst.type == X86_OP_REG:
            d = _reg(dst, insn)
            if src.type == X86_OP_REG: ir.append(I.MOV(d, _reg(src, insn)))
            elif src.type == X86_OP_IMM: ir.append(I.MOV(d, _imm(src.imm)))
            elif src.type == X86_OP_MEM: ir.append(I.LOAD(d, _mem(src, insn)))
            return insn.size, ir
        if dst.type == X86_OP_MEM:
            if src.type == X86_OP_REG: ir.append(I.STORE(_reg(src, insn), _mem(dst, insn)))
            elif src.type == X86_OP_IMM: ir.append(I.STORE(_imm(src.imm), _mem(dst, insn)))
            return insn.size, ir

    if m in ("add","sub","cmp") and ops[0].type in (X86_OP_REG, X86_OP_MEM):
        a1 = _reg(ops[0], insn) if ops[0].type == X86_OP_REG else _mem(ops[0], insn)
        a2 = (
            _reg(ops[1], insn) if ops[1].type == X86_OP_REG else
            _imm(ops[1].imm) if ops[1].type == X86_OP_IMM else
            _mem(ops[1], insn)
        )
        if m == "add":
            ir.append(I.ADD(a1 if isinstance(a1, I.Reg) else I.Reg("tmp"), a1, a2))
            if not isinstance(a1, I.Reg):
                ir[-1] = I.ADD(I.Reg("tmp"), a1, a2)
                ir.append(I.STORE(I.Reg("tmp"), a1))
        elif m == "sub":
            ir.append(I.SUB(a1 if isinstance(a1, I.Reg) else I.Reg("tmp"), a1, a2))
            if not isinstance(a1, I.Reg):
                ir[-1] = I.SUB(I.Reg("tmp"), a1, a2)
                ir.append(I.STORE(I.Reg("tmp"), a1))
        else:
            ir.append(I.CMP(a1, a2))
        return insn.size, ir

    if m == "jmp" and ops[0].type == X86_OP_IMM:
        ir.append(I.JMP(next_pc() + ops[0].imm))
        return insn.size, ir
    if m == "je" and ops[0].type == X86_OP_IMM:
        ir.append(I.JE(next_pc() + ops[0].imm))
        return insn.size, ir

    if m == "call" and ops[0].type == X86_OP_IMM:
        ir.append(I.CALL(next_pc() + ops[0].imm))
        return insn.size, ir
    if m == "ret":
        popb = ops[0].imm if len(ops) == 1 and ops[0].type == X86_OP_IMM else 0
        ir.append(I.RET(popb))
        return insn.size, ir

    if m == "push" and ops[0].type == X86_OP_REG:
        r = _reg(ops[0], insn)
        ir += [I.SUB(I.Reg("rsp"), I.Reg("rsp"), I.Imm(8)),
               I.STORE(r, I.Mem(base="rsp", width=8))]
        return insn.size, ir
    if m == "pop" and ops[0].type == X86_OP_REG:
        r = _reg(ops[0], insn)
        ir += [I.LOAD(r, I.Mem(base="rsp", width=8)),
               I.ADD(I.Reg("rsp"), I.Reg("rsp"), I.Imm(8))]
        return insn.size, ir

    if m == "leave":
        ir += [I.MOV(I.Reg("rsp"), I.Reg("rbp")),
               I.LOAD(I.Reg("rbp"), I.Mem(base="rsp", width=8)),
               I.ADD(I.Reg("rsp"), I.Reg("rsp"), I.Imm(8))]
        return insn.size, ir

    return insn.size, [I.NOP()]
