from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM

# Disassembler for x86_64 with operand detail
_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True

def step(instr_bytes: bytes, state):
    """
    Decode and execute one x86_64 instruction:
      - NOP: advance PC
      - MOV reg, reg|imm
      - ADD reg, reg|imm
    """
    insn = next(_md.disasm(instr_bytes, state.pc))
    mnemonic = insn.mnemonic
    ops = insn.operands

    # Helper to get register name & value
    def reg_name(op): return insn.reg_name(op.reg)
    def reg_val(name): return state.registers.get(name, 0)

    if mnemonic == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG:
        dest = reg_name(ops[0])
        if ops[1].type == X86_OP_REG:
            src = reg_name(ops[1])
            state.registers[dest] = reg_val(src)
        elif ops[1].type == X86_OP_IMM:
            state.registers[dest] = ops[1].imm

    elif mnemonic == "add" and len(ops) == 2 and ops[0].type == X86_OP_REG:
        dest = reg_name(ops[0])
        if ops[1].type == X86_OP_REG:
            src = reg_name(ops[1])
            val = reg_val(src)
        elif ops[1].type == X86_OP_IMM:
            val = ops[1].imm
        else:
            val = 0
        state.registers[dest] = reg_val(dest) + val

    # NOP or unhandled: no register change

    # Advance PC by instruction size
    state.pc += insn.size
    return state