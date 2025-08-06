from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from struct import pack, unpack_from

# Disassembler for x86_64 with full detail
_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True

def step(instr_bytes: bytes, state):
    """
    Decode and execute one x86_64 instruction:
      - MOV reg, reg|imm|[mem]
      - MOV [mem], reg
      - ADD reg, reg|imm
      - JMP absolute target
      - CMP reg, reg|imm  (sets ZF)
      - JE / JZ absolute target (if ZF)
      - Advance PC by default
    """
    # Disassemble starting at current PC offset
    insn = next(_md.disasm(instr_bytes[state.pc:], state.pc))
    mnemonic = insn.mnemonic
    ops = insn.operands

    # Helpers
    def reg_name(op): return insn.reg_name(op.reg)
    def get_reg(name): return state.registers.get(name, 0)

    # MOV reg, reg/imm/mem
    if mnemonic == "mov" and len(ops) == 2 and ops[0].type == X86_OP_REG:
        dest = reg_name(ops[0])
        # reg <- reg
        if ops[1].type == X86_OP_REG:
            state.registers[dest] = get_reg(reg_name(ops[1]))
        # reg <- imm
        elif ops[1].type == X86_OP_IMM:
            imm = ops[1].imm
            # Sign-extend 32-bit immediates to 64 bits
            if imm & 0xFFFFFFFF00000000 == 0 and imm & 0x80000000:
                imm |= 0xFFFFFFFF00000000
            state.registers[dest] = imm
        # reg <- [mem]
        elif ops[1].type == X86_OP_MEM:
            mem = ops[1].mem
            if mem.base:
                base = get_reg(insn.reg_name(mem.base))
            else:
                base = insn.address + insn.size  # RIP-relative
            addr = base + mem.disp
            state.registers[dest] = unpack_from("<Q", state.memory, addr)[0]
        state.pc += insn.size
        return state

    # MOV C7 /0: move imm32 -> r/m64 (covers register-direct when mod=3)
    elif mnemonic == "mov" and len(ops) == 2 and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_IMM:
        mem = ops[0].mem
        # direct register if no index and zero displacement
        if mem.base and mem.index == 0 and mem.disp == 0:
            dest = insn.reg_name(mem.base)
            imm = ops[1].imm
            if imm & 0xFFFFFFFF00000000 == 0 and imm & 0x80000000:
                imm |= 0xFFFFFFFF00000000
            state.registers[dest] = imm
            state.pc += insn.size
            return state

    # MOV [mem], reg (store)
    elif mnemonic == "mov" and len(ops) == 2 and ops[0].type == X86_OP_MEM and ops[1].type == X86_OP_REG:
        mem_op = ops[0].mem
        if mem_op.base:
            base = state.registers.get(insn.reg_name(mem_op.base), 0)
        else:
            base = insn.address + insn.size
        addr = base + mem_op.disp
        val = state.registers.get(reg_name(ops[1]), 0)
        data = pack("<Q", val)
        end = addr + len(data)
        if end > len(state.memory):
            state.memory.extend(b'\x00' * (end - len(state.memory)))
        state.memory[addr:end] = data
        state.pc += insn.size
        return state

    # ADD reg, reg/imm
    elif mnemonic == "add" and len(ops) == 2 and ops[0].type == X86_OP_REG:
        dest = reg_name(ops[0])
        val = (get_reg(reg_name(ops[1])) if ops[1].type == X86_OP_REG else
               ops[1].imm if ops[1].type == X86_OP_IMM else 0)
        state.registers[dest] = get_reg(dest) + val
        state.pc += insn.size
        return state

    # JMP absolute target
    elif mnemonic == "jmp" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        state.pc = ops[0].imm
        return state

    # CMP reg, reg/imm -> set ZF
    elif mnemonic == "cmp" and len(ops) == 2 and ops[0].type == X86_OP_REG:
        left = get_reg(reg_name(ops[0]))
        right = (get_reg(reg_name(ops[1])) if ops[1].type == X86_OP_REG else ops[1].imm)
        state.flags['ZF'] = (left - right == 0)
        state.pc += insn.size
        return state

    # JE / JZ absolute target
    elif mnemonic in ("je", "jz") and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        if state.flags.get('ZF', False):
            state.pc = ops[0].imm
            return state
        state.pc += insn.size
        return state

    # Default: advance PC
    state.pc += insn.size
    return state
