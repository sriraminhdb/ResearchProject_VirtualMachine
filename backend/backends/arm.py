from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM
from struct import unpack_from, pack

# Initialize Capstone for AArch64, little-endian mode
_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_md.detail = True

def step(instr_bytes: bytes, state):
    # If fewer than 4 bytes remain, advance past end so runner stops
    if state.pc + 4 > len(instr_bytes):
        state.pc += 4
        return state

    # Decode next instruction (or skip 4 bytes on failure)
    code = instr_bytes[state.pc:]
    try:
        insn = next(_md.disasm(code, state.pc))
    except StopIteration:
        state.pc += 4
        return state

    m   = insn.mnemonic
    ops = insn.operands

    ### B (unconditional, PC-relative) ###
    if m == "b" and len(ops) == 1 and ops[0].type == ARM64_OP_IMM:
        # ops[0].imm is a byte offset relative to current PC
        state.pc += ops[0].imm
        return state

    ### CBZ (PC-relative branch on zero) ###
    if m == "cbz" and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        reg  = insn.reg_name(ops[0].reg)
        val  = state.registers.get(reg, 0)
        if val == 0:
            # ops[1].imm is a byte offset relative to current PC
            state.pc += ops[1].imm
            return state

    ### MOV / MOVZ / MOVK ###
    if m in ("mov", "movz", "movk") and len(ops) == 2:
        dest = insn.reg_name(ops[0].reg)
        if ops[1].type == ARM64_OP_REG:
            src = insn.reg_name(ops[1].reg)
            state.registers[dest] = state.registers.get(src, 0)
        else:
            state.registers[dest] = ops[1].imm
        state.flags['ZF'] = (state.registers[dest] == 0)
        state.pc += insn.size
        return state

    ### ADD reg, reg/imm ###
    if m == "add" and len(ops) == 3 and ops[0].type == ARM64_OP_REG:
        dest = insn.reg_name(ops[0].reg)
        left = state.registers.get(insn.reg_name(ops[1].reg), 0)
        right = (
            ops[2].imm
            if ops[2].type == ARM64_OP_IMM
            else state.registers.get(insn.reg_name(ops[2].reg), 0)
        )
        res = left + right
        state.registers[dest] = res
        state.flags['ZF'] = (res == 0)
        state.pc += insn.size
        return state

    ### SUB / SUBS reg, reg/imm ###
    if m in ("sub", "subs") and len(ops) == 3 and ops[0].type == ARM64_OP_REG:
        dest = insn.reg_name(ops[0].reg)
        left = state.registers.get(insn.reg_name(ops[1].reg), 0)
        right = (
            ops[2].imm
            if ops[2].type == ARM64_OP_IMM
            else state.registers.get(insn.reg_name(ops[2].reg), 0)
        )
        res = left - right
        if m == "subs":
            state.registers[dest] = res
        state.flags['ZF'] = (res == 0)
        state.pc += insn.size
        return state

    ### LDR literal / LDR (immediate) ###
    if m == "ldr" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
        dest = insn.reg_name(ops[0].reg)
        mem  = ops[1].mem
        if mem.base == 0:
            # PC-relative (literal pool)
            addr = state.pc + mem.disp
        else:
            base = state.registers.get(insn.reg_name(mem.base), 0)
            addr = base + mem.disp
        if addr + 8 <= len(instr_bytes):
            val = unpack_from("<Q", instr_bytes, addr)[0]
        else:
            val = 0
        state.registers[dest] = val
        state.flags['ZF'] = (val == 0)
        state.pc += insn.size
        return state

    ### STR reg, [base, #imm] ###
    if m == "str" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
        src  = insn.reg_name(ops[0].reg)
        mem  = ops[1].mem
        base = state.registers.get(insn.reg_name(mem.base), 0)
        addr = base + mem.disp
        data = pack("<Q", state.registers.get(src, 0))
        end  = addr + len(data)
        if end > len(state.memory):
            state.memory.extend(b'\x00' * (end - len(state.memory)))
        state.memory[addr:end] = data
        state.pc += insn.size
        return state

    # Default case: just advance PC
    state.pc += insn.size
    return state