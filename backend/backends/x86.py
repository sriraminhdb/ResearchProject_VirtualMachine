# backend/backends/x86.py
from struct import pack, unpack_from
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

# Capstone disassembler (x86-64, detailed mode)
_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True

# -------- register helpers: map sub-width names to canonical 64-bit --------
_alias32_to64 = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "esp": "rsp", "ebp": "rbp",
}
_alias16_to64 = {
    "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
    "si": "rsi", "di": "rdi", "sp": "rsp", "bp": "rbp",
}
_alias8_to64 = {
    "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
    "ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx",
    "sil": "rsi", "dil": "rdi", "spl": "rsp", "bpl": "rbp",
}

def _canon64(name: str) -> str:
    """Map 8/16/32-bit GPR names (and r8d/w/b..r15d/w/b) to their 64-bit canonical names."""
    n = name.lower()
    if n in _alias32_to64: return _alias32_to64[n]
    if n in _alias16_to64: return _alias16_to64[n]
    if n in _alias8_to64:  return _alias8_to64[n]
    # r8d..r15d, r8w..r15w, r8b..r15b -> r8..r15
    if len(n) >= 3 and n[0] == "r" and n[-1] in ("d", "w", "b"):
        base = n[:-1]
        try:
            idx = int(base[1:])
            if 8 <= idx <= 15:
                return base
        except ValueError:
            pass
    return n

def _get(state, name):
    return state.registers.get(_canon64(name), 0)

def _set(state, name, val):
    state.registers[_canon64(name)] = val & ((1 << 64) - 1)


def step(instr_bytes: bytes, state):
    """
    Execute a single x86-64 instruction at state.pc.

    Supported (subset for project tests):
      - Control flow: jmp rel/abs, je rel/abs, call rel/abs, ret, ret imm16, leave
      - Stack: push reg, pop reg
      - Moves: mov/movabs (reg, imm/reg/mem), full 64-bit little-endian stores/loads
               (robust C7/C6 reg-target handling)
      - ALU/flags: add, sub, cmp (sets ZF)
      - Addressing: [base + index*scale + disp]

    Orchestrator flags used:
      - state.flags['ZF']     : zero flag
      - state.flags['_depth'] : call depth (+ on call, - on ret)
      - state.flags['_halt']  : request run loop to stop (after top-level ret)
      - state.code_end        : end of original code; stack appended after
    """
    # Decode from the current PC
    code = instr_bytes[state.pc:]
    insn = next(_md.disasm(code, state.pc))

    # ---------- ultra-early C7/C6 fix (imm -> r/m with ModRM.mod==11 → register) ----------
    def _mov_imm_reg_fast(insn_obj):
        b = bytes(insn_obj.bytes)
        i = 0
        # parse optional REX (0x40..0x4F)
        rex = 0
        while i < len(b) and 0x40 <= b[i] <= 0x4F:
            rex = b[i]; i += 1
        if i >= len(b): return None
        op = b[i]; i += 1
        if op not in (0xC7, 0xC6):  # C7 imm32 to r/m, C6 imm8 to r/m
            return None
        if i >= len(b): return None
        modrm = b[i]; i += 1
        mod = (modrm >> 6) & 0x3
        rm  = (modrm & 0x7)
        if mod != 0b11:
            return None  # not register-direct
        rex_b = 1 if (rex & 0x01) else 0
        reg_idx = rm + (rex_b * 8)
        regs64 = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                  "r8","r9","r10","r11","r12","r13","r14","r15"]
        if not (0 <= reg_idx < len(regs64)):
            return None
        # immediate
        if op == 0xC7:
            if i + 4 > len(b): return None
            imm = int.from_bytes(b[i:i+4], "little", signed=False)
            if (rex & 0x08) and (imm & 0x80000000):
                imm |= (~0xffffffff) & ((1 << 64) - 1)  # sign-extend imm32 under REX.W
        else:
            if i + 1 > len(b): return None
            imm8 = b[i]
            if (rex & 0x08) and (imm8 & 0x80):
                imm = imm8 | ((~0xff) & ((1 << 64) - 1))  # sign-extend imm8 under REX.W
            else:
                imm = imm8
        return regs64[reg_idx], imm

    # Try fast-path first (works regardless of Capstone operand typing)
    fast = _mov_imm_reg_fast(insn)
    if fast is not None:
        dest, imm = fast
        _set(state, dest, imm)
        state.pc += insn.size
        return state

    # ---------- helpers ----------
    m, ops = insn.mnemonic, insn.operands

    def cap_reg_name(op_or_id):
        if isinstance(op_or_id, int):
            return insn.reg_name(op_or_id)
        return insn.reg_name(op_or_id.reg)

    def _ensure(length):
        if length > len(state.memory):
            state.memory.extend(b"\x00" * (length - len(state.memory)))

    def read_op(op):
        if op.type == X86_OP_REG:
            return _get(state, cap_reg_name(op))
        if op.type == X86_OP_IMM:
            return op.imm
        if op.type == X86_OP_MEM:
            mem = op.mem
            base = cap_reg_name(mem.base) if mem.base != 0 else None
            idx  = cap_reg_name(mem.index) if mem.index != 0 else None
            addr = 0
            if base: addr += _get(state, base)
            if idx:  addr += _get(state, idx) * (mem.scale or 1)
            addr += mem.disp  # signed
            _ensure(addr + 8)
            return unpack_from("<Q", state.memory, addr)[0]
        return 0

    def write_reg(op, val):
        _set(state, cap_reg_name(op), val)

    def write_mem(op, val):
        mem = op.mem
        base = cap_reg_name(mem.base) if mem.base != 0 else None
        idx  = cap_reg_name(mem.index) if mem.index != 0 else None
        addr = 0
        if base: addr += _get(state, base)
        if idx:  addr += _get(state, idx) * (mem.scale or 1)
        addr += mem.disp
        data = pack("<Q", val & ((1 << 64) - 1))
        _ensure(addr + 8)
        state.memory[addr:addr+8] = data

    # ----- robust relative-or-absolute target resolver for control flow -----
    def _target_abs_or_rel(op_imm):
        """
        Capstone x86 can expose op.imm as either:
          - relative displacement (usual), or
          - absolute code address (some builds).
        If op_imm is inside [0, code_end), treat as absolute; else, treat as relative.
        """
        imm = int(op_imm)
        code_end = getattr(state, "code_end", len(state.memory))
        if 0 <= imm < code_end:
            return imm
        return insn.address + insn.size + imm

    # ---------- control flow ----------
    if m == "jmp" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        state.pc = _target_abs_or_rel(ops[0].imm)
        return state

    if m == "je" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        if state.flags.get("ZF", False):
            state.pc = _target_abs_or_rel(ops[0].imm)
            return state

    if m == "call" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        ret_addr = insn.address + insn.size
        state.registers["rsp"] -= 8
        sp = state.registers["rsp"]
        _ensure(sp + 8)
        state.memory[sp:sp+8] = pack("<Q", ret_addr)
        state.pc = _target_abs_or_rel(ops[0].imm)
        state.flags["_depth"] = int(state.flags.get("_depth", 0)) + 1
        return state

    if m == "ret":
        sp = state.registers.get("rsp", 0)
        if sp + 8 > len(state.memory):
            state.pc = getattr(state, "code_end", len(state.memory))
            state.flags["_halt"] = True
            return state
        ret_addr = unpack_from("<Q", state.memory, sp)[0]
        state.registers["rsp"] = sp + 8
        if len(ops) == 1 and ops[0].type == X86_OP_IMM:
            state.registers["rsp"] += (int(ops[0].imm) & 0xFFFF)
        state.pc = ret_addr
        depth = int(state.flags.get("_depth", 0)) - 1
        state.flags["_depth"] = max(depth, 0)
        if state.flags["_depth"] == 0:
            state.flags["_halt"] = True
        return state

    if m == "leave":
        rbp = state.registers.get("rbp", 0)
        state.registers["rsp"] = rbp
        sp = state.registers["rsp"]
        if sp + 8 <= len(state.memory):
            old = unpack_from("<Q", state.memory, sp)[0]
            state.registers["rbp"] = old
            state.registers["rsp"] = sp + 8
        state.pc += insn.size
        return state

    # ---------- stack ops ----------
    if m == "push" and len(ops) == 1 and ops[0].type == X86_OP_REG:
        val = read_op(ops[0])
        state.registers["rsp"] -= 8
        sp = state.registers["rsp"]
        _ensure(sp + 8)
        state.memory[sp:sp+8] = pack("<Q", val)
        state.pc += insn.size
        return state

    if m == "pop" and len(ops) == 1 and ops[0].type == X86_OP_REG:
        sp = state.registers["rsp"]
        _ensure(sp + 8)
        val = unpack_from("<Q", state.memory, sp)[0]
        state.registers["rsp"] = sp + 8
        write_reg(ops[0], val)
        state.pc += insn.size
        return state

    # ---------- arithmetic / flags ----------
    if m == "add" and len(ops) == 2 and ops[0].type in (X86_OP_REG, X86_OP_MEM):
        res = (read_op(ops[0]) + read_op(ops[1])) & ((1 << 64) - 1)
        (write_reg if ops[0].type == X86_OP_REG else write_mem)(ops[0], res)
        state.pc += insn.size
        return state

    if m == "sub" and len(ops) == 2 and ops[0].type in (X86_OP_REG, X86_OP_MEM):
        res = (read_op(ops[0]) - read_op(ops[1])) & ((1 << 64) - 1)
        (write_reg if ops[0].type == X86_OP_REG else write_mem)(ops[0], res)
        state.pc += insn.size
        return state

    if m == "cmp" and len(ops) == 2:
        state.flags["ZF"] = (read_op(ops[0]) - read_op(ops[1])) == 0
        state.pc += insn.size
        return state

    # ---------- mov / movabs ----------
    if m in ("mov", "movabs") and len(ops) == 2:
        # (A) Additional Capstone-ModRM fallback:
        #     if dest shows up as MEM but ModRM.mod==11, it's actually a REG (C7/C6 quirk)
        try:
            if ops[1].type == X86_OP_IMM and getattr(insn, "modrm", None) is not None:
                mod = (insn.modrm >> 6) & 0x3
                rm  =  insn.modrm       & 0x7
                rex_b = 1 if (getattr(insn, "rex", 0) & 0x01) else 0
                if mod == 0b11:
                    reg_idx = rm + (rex_b * 8)
                    regs64 = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                              "r8","r9","r10","r11","r12","r13","r14","r15"]
                    if 0 <= reg_idx < len(regs64):
                        _set(state, regs64[reg_idx], ops[1].imm)
                        state.pc += insn.size
                        return state
        except Exception:
            pass

        # (B) Normal register destination
        if ops[0].type == X86_OP_REG:
            write_reg(ops[0], read_op(ops[1]))
            state.pc += insn.size
            return state

        # (C) Genuine memory destination
        if ops[0].type == X86_OP_MEM:
            write_mem(ops[0], read_op(ops[1]))
            state.pc += insn.size
            return state

    # ---------- default ----------
    state.pc += insn.size
    return state
