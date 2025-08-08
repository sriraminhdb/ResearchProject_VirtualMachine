from struct import pack, unpack_from
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_REG_SP

_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_md.detail = True

def step(instr_bytes: bytes, state):
    code = instr_bytes[state.pc:]
    insn = next(_md.disasm(code, state.pc))
    m, ops = insn.mnemonic, insn.operands

    def rname(opreg): return insn.reg_name(opreg)

    # ---- branches ----
    # B imm (absolute from Capstone)
    if m == "b" and len(ops) == 1 and ops[0].type == ARM64_OP_IMM:
        state.pc = ops[0].imm
        return state

    # CBZ reg, imm (relative from next pc)
    if m == "cbz" and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        if state.flags.get("ZF", False):
            state.pc = insn.address + insn.size + ops[1].imm
            return state

    # BL imm (absolute)
    if m == "bl" and len(ops) == 1 and ops[0].type == ARM64_OP_IMM:
        state.registers["x30"] = insn.address + insn.size
        state.pc = ops[0].imm
        return state

    # RET → branch to x30
    if m == "ret":
        state.pc = state.registers.get("x30", state.pc + insn.size)
        return state

    # ---- mov ----
    if m.startswith("mov") and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        dest = rname(ops[0].reg)
        if ops[1].type == ARM64_OP_REG:
            state.registers[dest] = state.registers.get(rname(ops[1].reg), 0)
        elif ops[1].type == ARM64_OP_IMM:
            state.registers[dest] = ops[1].imm

    # ---- add ----
    elif m == "add" and len(ops) == 3 and ops[0].type == ARM64_OP_REG:
        dest = rname(ops[0].reg)
        def get_val(op):
            if op.type == ARM64_OP_REG: return state.registers.get(rname(op.reg), 0)
            if op.type == ARM64_OP_IMM: return op.imm
            return 0
        state.registers[dest] = get_val(ops[1]) + get_val(ops[2])

    # ---- ldr/str (64-bit) ----
    elif m == "ldr" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
        dest = rname(ops[0].reg)
        mem = ops[1].mem
        base = state.registers.get(rname(mem.base), 0)
        addr = base + mem.disp
        val = unpack_from("<Q", state.memory, addr)[0]
        state.registers[dest] = val

    elif m == "str" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
        src = rname(ops[0].reg)
        mem = ops[1].mem
        base = state.registers.get(rname(mem.base), 0)
        addr = base + mem.disp
        data = pack("<Q", state.registers.get(src, 0))
        end = addr + 8
        if end > len(state.memory):
            state.memory.extend(b"\x00" * (end - len(state.memory)))
        state.memory[addr:end] = data

    # ---- stp/ldp with sp (stack) ----
    elif m == "stp" and len(ops) == 3 and ops[2].type == ARM64_OP_MEM and ops[2].mem.base == ARM64_REG_SP:
        # pre-index (e.g., [sp,#-16]!)
        reg1 = rname(ops[0].reg)
        reg2 = rname(ops[1].reg)
        mem = ops[2].mem
        disp = mem.disp  # typically -16
        state.registers["sp"] += disp
        addr = state.registers["sp"]
        data1 = pack("<Q", state.registers.get(reg1, 0))
        data2 = pack("<Q", state.registers.get(reg2, 0))
        end = addr + 16
        if end > len(state.memory):
            state.memory.extend(b"\x00" * (end - len(state.memory)))
        state.memory[addr:addr+8] = data1
        state.memory[addr+8:addr+16] = data2

    elif m == "ldp" and len(ops) == 3 and ops[2].type == ARM64_OP_MEM and ops[2].mem.base == ARM64_REG_SP:
        # post-index (e.g., [sp],#16)
        mem = ops[2].mem
        disp = mem.disp  # typically +16
        addr = state.registers["sp"]
        reg1 = rname(ops[0].reg)
        reg2 = rname(ops[1].reg)
        state.registers[reg1] = unpack_from("<Q", state.memory, addr)[0]
        state.registers[reg2] = unpack_from("<Q", state.memory, addr + 8)[0]
        state.registers["sp"] += disp

    # ---- cmp/subs → ZF ----
    elif m in ("cmp", "subs") and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        left = state.registers.get(rname(ops[0].reg), 0)
        right = ops[1].imm if ops[1].type == ARM64_OP_IMM else state.registers.get(rname(ops[1].reg), 0)
        state.flags["ZF"] = (left - right) == 0

    # Default: advance PC
    state.pc += insn.size
    return state
