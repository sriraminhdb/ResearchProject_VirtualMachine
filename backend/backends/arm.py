from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

# Disassembler for AArch64 (little-endian)
_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_md.detail = False

def step(instr_bytes: bytes, state):
    """
    Decode and execute one AArch64 instruction.
    Currently only handles NOP (0x1f2003d5), advancing PC by its size (4).
    """
    insn = next(_md.disasm(instr_bytes, state.pc))
    state.pc += insn.size
    return state
