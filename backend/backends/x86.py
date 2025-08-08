from struct import pack, unpack_from
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True

def _get(state, name):
    return state.registers.get(name, 0)

def _set(state, name, val):
    state.registers[name] = val & ((1 << 64) - 1)

def step(instr_bytes: bytes, state):
    # Decode from current PC
    code = instr_bytes[state.pc:]
    insn = next(_md.disasm(code, state.pc))
    m, ops = insn.mnemonic, insn.operands

    # Accept operand object (.reg) or raw register id (int)
    def reg_name(op_or_id):
        if isinstance(op_or_id, int):
            return insn.reg_name(op_or_id)
        return insn.reg_name(op_or_id.reg)

    # ---- operand helpers ----
    def read_op(op):
        if op.type == X86_OP_REG:
            return _get(state, reg_name(op))
        elif op.type == X86_OP_IMM:
            return op.imm
        elif op.type == X86_OP_MEM:
            mem = op.mem
            base = reg_name(mem.base) if mem.base != 0 else None
            idx  = reg_name(mem.index) if mem.index != 0 else None
            addr = 0
            if base:
                addr += _get(state, base)
            if idx:
                addr += _get(state, idx) * (mem.scale or 1)
            addr += mem.disp
            return unpack_from("<Q", state.memory, addr)[0]
        return 0

    def write_reg(op, val):
        _set(state, reg_name(op), val)

    def write_mem(op, val):
        mem = op.mem
        base = reg_name(mem.base) if mem.base != 0 else None
        idx  = reg_name(mem.index) if mem.index != 0 else None
        addr = 0
        if base:
            addr += _get(state, base)
        if idx:
            addr += _get(state, idx) * (mem.scale or 1)
        addr += mem.disp
        data = pack("<Q", val & ((1 << 64) - 1))
        end = addr + 8
        if end > len(state.memory):
            state.memory.extend(b"\x00" * (end - len(state.memory)))
        state.memory[addr:end] = data

    # ---- control flow ----
    # jmp rel8/rel32
    if m == "jmp" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        state.pc = insn.address + insn.size + ops[0].imm
        return state

    # je rel8/rel32
    if m == "je" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        if state.flags.get("ZF", False):
            state.pc = insn.address + insn.size + ops[0].imm
            return state

    # call rel32 (target is relative to next instruction)
    if m == "call" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        ret_addr = insn.address + insn.size
        state.registers["rsp"] -= 8
        addr = state.registers["rsp"]
        state.memory[addr:addr+8] = pack("<Q", ret_addr)
        state.pc = ret_addr + ops[0].imm
        return state

    # ret (graceful if stack empty)
    if m == "ret":
        addr = state.registers.get("rsp", 0)
        if addr + 8 > len(state.memory):  # nothing to pop → end
            state.pc = getattr(state, "code_end", len(state.memory))
            return state
        ret_addr = unpack_from("<Q", state.memory, addr)[0]
        state.registers["rsp"] = addr + 8
        state.pc = ret_addr
        return state

    # ---- stack ops ----
    if m == "push" and len(ops) == 1 and ops[0].type == X86_OP_REG:
        val = read_op(ops[0])
        state.registers["rsp"] -= 8
        addr = state.registers["rsp"]
        state.memory[addr:addr+8] = pack("<Q", val)
        state.pc += insn.size
        return state

    if m == "pop" and len(ops) == 1 and ops[0].type == X86_OP_REG:
        addr = state.registers["rsp"]
        val = unpack_from("<Q", state.memory, addr)[0]
        state.registers["rsp"] += 8
        write_reg(ops[0], val)
        state.pc += insn.size
        return state

    # ---- arithmetic / flags ----
    if m == "add" and len(ops) == 2 and ops[0].type in (X86_OP_REG, X86_OP_MEM):
        lhs = read_op(ops[0])
        rhs = read_op(ops[1])
        res = (lhs + rhs) & ((1 << 64) - 1)
        if ops[0].type == X86_OP_REG:
            write_reg(ops[0], res)
        else:
            write_mem(ops[0], res)
        state.pc += insn.size
        return state

    if m == "cmp" and len(ops) == 2:
        left = read_op(ops[0])
        right = read_op(ops[1])
        state.flags["ZF"] = (left - right) == 0
        state.pc += insn.size
        return state

    # ---- mov (Capstone may emit 'movabs' for imm64) ----
    if m in ("mov", "movabs") and len(ops) == 2:
        src_val = read_op(ops[1])
        if ops[0].type == X86_OP_REG:
            write_reg(ops[0], src_val)
        elif ops[0].type == X86_OP_MEM:
            write_mem(ops[0], src_val)
        state.pc += insn.size
        return state

    # Default: advance PC
    state.pc += insn.size
    return state
