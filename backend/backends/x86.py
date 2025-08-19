from __future__ import annotations
from struct import pack, unpack_from
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM

_md = Cs(CS_ARCH_X86, CS_MODE_64)
_md.detail = True

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
    n = name.lower()
    if n in _alias32_to64: return _alias32_to64[n]
    if n in _alias16_to64: return _alias16_to64[n]
    if n in _alias8_to64:  return _alias8_to64[n]
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

def _ensure(mem, length: int):
    if length < 0:
        return
    if length > len(mem):
        mem.extend(b"\x00" * (length - len(mem)))

def step(instr_bytes: bytes, state):
    """
    Execute a single x86-64 instruction at state.pc.

    Supported (subset for project tests):
      - Control flow: jmp rel/abs, je rel/abs, call rel32/abs, ret, ret imm16, leave, nop
      - Stack: push reg, pop reg
      - Moves: mov/movabs (reg, imm/reg/mem), C7/C6 direct-reg quirk handled
      - ALU/flags: add, sub, cmp (sets ZF), xor (ZF on result)
      - Addressing: [base + index*scale + disp]
      - lea r64, [mem]
    """
    code = instr_bytes[state.pc:]
    insn = next(_md.disasm(code, state.pc))

    def _mov_imm_reg_fast(insn_obj):
        b = bytes(insn_obj.bytes)
        i = 0
        rex = 0
        while i < len(b) and 0x40 <= b[i] <= 0x4F:
            rex = b[i]; i += 1
        if i >= len(b): return None
        op = b[i]; i += 1
        if op not in (0xC7, 0xC6):
            return None
        if i >= len(b): return None
        modrm = b[i]; i += 1
        mod = (modrm >> 6) & 0x3
        rm  = (modrm & 0x7)
        if mod != 0b11:
            return None
        rex_b = 1 if (rex & 0x01) else 0
        reg_idx = rm + (rex_b * 8)
        regs64 = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                  "r8","r9","r10","r11","r12","r13","r14","r15"]
        if not (0 <= reg_idx < len(regs64)):
            return None
        if op == 0xC7:
            if i + 4 > len(b): return None
            imm = int.from_bytes(b[i:i+4], "little", signed=False)
            if (rex & 0x08) and (imm & 0x80000000):
                imm |= (~0xffffffff) & ((1 << 64) - 1)
        else:
            if i + 1 > len(b): return None
            imm8 = b[i]
            if (rex & 0x08) and (imm8 & 0x80):
                imm = imm8 | ((~0xff) & ((1 << 64) - 1))
            else:
                imm = imm8
        return regs64[reg_idx], imm

    fast = _mov_imm_reg_fast(insn)
    if fast is not None:
        dest, imm = fast
        _set(state, dest, imm)
        state.pc += insn.size
        return state

    m, ops = insn.mnemonic, insn.operands

    def cap_reg_name(op_or_id):
        if isinstance(op_or_id, int):
            return insn.reg_name(op_or_id)
        return insn.reg_name(op_or_id.reg)

    def read_op(op):
        if op.type == X86_OP_REG:
            return _get(state, cap_reg_name(op))
        if op.type == X86_OP_IMM:
            return int(op.imm)
        if op.type == X86_OP_MEM:
            mem = op.mem
            base = cap_reg_name(mem.base) if mem.base != 0 else None
            idx  = cap_reg_name(mem.index) if mem.index != 0 else None
            addr = 0
            if base: addr += _get(state, base)
            if idx:  addr += _get(state, idx) * (mem.scale or 1)
            addr += mem.disp
            _ensure(state.memory, addr + 8)
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
        _ensure(state.memory, addr + 8)
        state.memory[addr:addr+8] = data

    if m == "nop":
        state.pc += insn.size
        return state

    if m == "jmp" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        state.pc = int(ops[0].imm)
        return state

    if m == "je" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        if state.flags.get("ZF", False):
            state.pc = int(ops[0].imm)
            return state

    if m == "call" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        ret_addr = insn.address + insn.size
        state.registers["rsp"] = _get(state, "rsp") - 8
        sp = state.registers["rsp"]
        _ensure(state.memory, sp + 8)
        state.memory[sp:sp+8] = pack("<Q", ret_addr)
        state.pc = int(ops[0].imm)
        state.flags["_depth"] = int(state.flags.get("_depth", 0)) + 1
        return state

    if m == "ret":
        sp = _get(state, "rsp")
        if sp + 8 > len(state.memory):
            return state
        ret_addr = unpack_from("<Q", state.memory, sp)[0]
        state.registers["rsp"] = sp + 8
        if len(ops) == 1 and ops[0].type == X86_OP_IMM:
            state.registers["rsp"] += (int(ops[0].imm) & 0xFFFF)
        state.pc = ret_addr
        depth = int(state.flags.get("_depth", 0)) - 1
        state.flags["_depth"] = max(depth, 0)
        return state

    if m == "leave":
        rbp = _get(state, "rbp")
        state.registers["rsp"] = rbp
        sp = _get(state, "rsp")
        if sp + 8 <= len(state.memory):
            old = unpack_from("<Q", state.memory, sp)[0]
            state.registers["rbp"] = old
            state.registers["rsp"] = sp + 8
        state.pc += insn.size
        return state

    if m == "push" and len(ops) == 1 and ops[0].type == X86_OP_REG:
        val = read_op(ops[0])
        state.registers["rsp"] = _get(state, "rsp") - 8
        sp = _get(state, "rsp")
        _ensure(state.memory, sp + 8)
        state.memory[sp:sp+8] = pack("<Q", val)
        state.pc += insn.size
        return state

    if m == "pop" and len(ops) == 1 and ops[0].type == X86_OP_REG:
        sp = _get(state, "rsp")
        _ensure(state.memory, sp + 8)
        val = unpack_from("<Q", state.memory, sp)[0]
        state.registers["rsp"] = sp + 8
        write_reg(ops[0], val)
        state.pc += insn.size
        return state

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

    if m == "xor" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
        val = _get(state, cap_reg_name(ops[0])) ^ _get(state, cap_reg_name(ops[1]))
        write_reg(ops[0], val)
        state.flags["ZF"] = (val == 0)
        state.pc += insn.size
        return state

    if m == "cmp" and len(ops) == 2:
        state.flags["ZF"] = (read_op(ops[0]) - read_op(ops[1])) == 0
        state.pc += insn.size
        return state

    if m == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
        mem = ops[1].mem
        base = cap_reg_name(mem.base) if mem.base != 0 else None
        idx  = cap_reg_name(mem.index) if mem.index != 0 else None
        addr = 0
        if base: addr += _get(state, base)
        if idx:  addr += _get(state, idx) * (mem.scale or 1)
        addr += mem.disp
        write_reg(ops[0], addr & ((1 << 64) - 1))
        state.pc += insn.size
        return state

    if m in ("mov", "movabs") and len(ops) == 2:
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
                        _set(state, regs64[reg_idx], int(ops[1].imm))
                        state.pc += insn.size
                        return state
        except Exception:
            pass

        if ops[0].type == X86_OP_REG:
            write_reg(ops[0], read_op(ops[1]))
            state.pc += insn.size
            return state

        if ops[0].type == X86_OP_MEM:
            write_mem(ops[0], read_op(ops[1]))
            state.pc += insn.size
            return state

    state.pc += insn.size
    return state

from backend.ir import (
    IRNop, IRMovImm, IRMovReg, IRAdd, IRSub, IRLoad, IRStore,
    IRCmp, IRJmp, IRJe, IRLea, IRXor
)

def decode_to_ir(instr_bytes: bytes, state):
    code = instr_bytes[state.pc:]
    insn = next(_md.disasm(code, state.pc))
    m, ops = insn.mnemonic, insn.operands
    pc = insn.address
    size = insn.size
    ir = []

    def rn(o): 
        return _canon64(insn.reg_name(o.reg))

    if m == "nop":
        ir = [IRNop()]

    elif m in ("mov", "movabs") and len(ops) == 2:
        dst, src = ops[0], ops[1]
        if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
            ir = [IRMovImm(rn(dst), int(src.imm))]
        elif dst.type == X86_OP_REG and src.type == X86_OP_REG:
            ir = [IRMovReg(rn(dst), rn(src))]
        elif dst.type == X86_OP_REG and src.type == X86_OP_MEM:
            mem = src.mem
            base = insn.reg_name(mem.base) if mem.base != 0 else None
            idx  = insn.reg_name(mem.index) if mem.index != 0 else None
            ir = [IRLoad(rn(dst), base=_canon64(base) if base else None,
                         disp=mem.disp, index=_canon64(idx) if idx else None, scale=mem.scale or 1)]
        elif dst.type == X86_OP_MEM and src.type in (X86_OP_REG, X86_OP_IMM):
            mem = dst.mem
            base = insn.reg_name(mem.base) if mem.base != 0 else None
            idx  = insn.reg_name(mem.index) if mem.index != 0 else None
            if src.type == X86_OP_REG:
                ir = [IRStore(_canon64(insn.reg_name(src.reg)),
                              base=_canon64(base) if base else None,
                              disp=mem.disp, index=_canon64(idx) if idx else None, scale=mem.scale or 1)]
            else:
                tmp = "r11"
                ir = [IRMovImm(tmp, int(src.imm)),
                      IRStore(tmp, base=_canon64(base) if base else None,
                              disp=mem.disp, index=_canon64(idx) if idx else None, scale=mem.scale or 1)]

    elif m == "add" and len(ops) == 2 and ops[0].type == X86_OP_REG:
        if ops[1].type == X86_OP_IMM:
            ir = [IRAdd(rn(ops[0]), rn(ops[0]), int(ops[1].imm))]
        else:
            ir = [IRAdd(rn(ops[0]), rn(ops[0]), rn(ops[1]))]

    elif m == "sub" and len(ops) == 2 and ops[0].type == X86_OP_REG:
        if ops[1].type == X86_OP_IMM:
            ir = [IRSub(rn(ops[0]), rn(ops[0]), int(ops[1].imm))]
        else:
            ir = [IRSub(rn(ops[0]), rn(ops[0]), rn(ops[1]))]

    elif m == "cmp" and len(ops) == 2:
        a = rn(ops[0]) if ops[0].type == X86_OP_REG else int(ops[0].imm)
        b = rn(ops[1]) if ops[1].type == X86_OP_REG else int(ops[1].imm)
        ir = [IRCmp(a, b)]

    elif m == "je" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        ir = [IRJe(int(ops[0].imm))]

    elif m == "jmp" and len(ops) == 1 and ops[0].type == X86_OP_IMM:
        ir = [IRJmp(int(ops[0].imm))]

    elif m == "lea" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
        mem = ops[1].mem
        base = insn.reg_name(mem.base) if mem.base != 0 else None
        idx  = insn.reg_name(mem.index) if mem.index != 0 else None
        ir = [IRLea(rn(ops[0]), base=_canon64(base) if base else None,
                    disp=mem.disp, index=_canon64(idx) if idx else None, scale=mem.scale or 1)]

    elif m == "xor" and len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
        ir = [IRXor(rn(ops[0]), rn(ops[0]), rn(ops[1]))]

    else:
        ir = [IRNop()]

    return ir, size
