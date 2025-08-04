from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# Disassembler for x86_64
_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = False

def step(instr_bytes: bytes, state):
    """
    Decode and execute one x86_64 instruction.
    Currently only handles NOP (0x90), advancing PC by its size.
    """
    # Disassemble one instruction at current PC
    insn = next(_md.disasm(instr_bytes, state.pc))
    # Advance PC
    state.pc += insn.size
    return state