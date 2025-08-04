from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM

# Disassembler for AArch64 little-endian
_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_md.detail = True

def step(instr_bytes: bytes, state):
    """
    Decode and execute one AArch64 instruction:
      - MOV   reg, reg|imm
      - ADD   reg, reg|imm, reg|imm
      - (NOP and others simply advance PC)
    """
    insn = next(_md.disasm(instr_bytes, state.pc))
    mnemonic = insn.mnemonic
    ops = insn.operands

    # MOV: 2 operands
    if mnemonic.startswith("mov") and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        dest = insn.reg_name(ops[0].reg)
        if ops[1].type == ARM64_OP_REG:
            src = insn.reg_name(ops[1].reg)
            state.registers[dest] = state.registers.get(src, 0)
        elif ops[1].type == ARM64_OP_IMM:
            state.registers[dest] = ops[1].imm

    # ADD: 3 operands
    elif mnemonic == "add" and len(ops) == 3 and ops[0].type == ARM64_OP_REG:
        dest = insn.reg_name(ops[0].reg)

        def get_val(op):
            if op.type == ARM64_OP_REG:
                return state.registers.get(insn.reg_name(op.reg), 0)
            elif op.type == ARM64_OP_IMM:
                return op.imm
            return 0

        val1 = get_val(ops[1])
        val2 = get_val(ops[2])
        state.registers[dest] = val1 + val2

    # Advance PC by instruction size
    state.pc += insn.size
    return state
