from __future__ import annotations
from struct import pack, unpack_from
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

_md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
_md.detail = True

def _get(state, name: str) -> int:
    return state.registers.get(name.lower(), 0)

def _set(state, name: str, val: int):
    state.registers[name.lower()] = val & ((1 << 64) - 1)

def _ensure(mem, length: int):
    if length < 0:
        return
    if length > len(mem):
        mem.extend(b"\x00" * (length - len(mem)))

def step(instr_bytes: bytes, state):
    """
    Execute one AArch64 instruction at state.pc.

    Supported (subset for project tests):
      - Control flow: b imm, cbz reg, bl imm (link to x30), ret (uses x30), nop
      - Moves/ALU: mov/movz, add, sub, subs, cmp (sets ZF)
      - ldr/str [base + imm]
    """
    code = instr_bytes[state.pc:]
    insn = next(_md.disasm(code, state.pc))
    m, ops = insn.mnemonic, insn.operands

    def rname(op_or_id):
        if isinstance(op_or_id, int):
            return insn.reg_name(op_or_id)
        return insn.reg_name(op_or_id.reg)

    def read_mem(base_reg: str, disp: int) -> int:
        addr = _get(state, base_reg) + disp
        _ensure(state.memory, addr + 8)
        return unpack_from("<Q", state.memory, addr)[0]

    def write_mem(base_reg: str, disp: int, val: int):
        addr = _get(state, base_reg) + disp
        _ensure(state.memory, addr + 8)
        state.memory[addr:addr+8] = pack("<Q", val & ((1 << 64) - 1))

    if m == "nop":
        state.pc += insn.size
        return state

    if m in ("mov", "movz", "movn", "movk") and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        if ops[1].type == ARM64_OP_IMM:
            _set(state, rname(ops[0]), int(ops[1].imm))
        elif ops[1].type == ARM64_OP_REG:
            _set(state, rname(ops[0]), _get(state, rname(ops[1])))
        state.pc += insn.size
        return state

    if m == "add" and len(ops) == 3 and ops[0].type == ARM64_OP_REG:
        a = _get(state, rname(ops[1]))
        b = int(ops[2].imm) if ops[2].type == ARM64_OP_IMM else _get(state, rname(ops[2]))
        _set(state, rname(ops[0]), (a + b) & ((1 << 64) - 1))
        state.pc += insn.size
        return state

    if m in ("sub", "subs") and len(ops) == 3 and ops[0].type == ARM64_OP_REG:
        a = _get(state, rname(ops[1]))
        b = int(ops[2].imm) if ops[2].type == ARM64_OP_IMM else _get(state, rname(ops[2]))
        res = (a - b) & ((1 << 64) - 1)
        _set(state, rname(ops[0]), res)
        if m == "subs":
            state.flags["ZF"] = (res == 0)
        state.pc += insn.size
        return state

    if m == "cmp" and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        a = _get(state, rname(ops[0]))
        b = int(ops[1].imm) if ops[1].type == ARM64_OP_IMM else _get(state, rname(ops[1]))
        state.flags["ZF"] = ((a - b) & ((1 << 64) - 1)) == 0
        state.pc += insn.size
        return state

    if m == "ldr" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
        mem = ops[1].mem
        _set(state, rname(ops[0]), read_mem(rname(mem.base), mem.disp))
        state.pc += insn.size
        return state

    if m == "str" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
        mem = ops[1].mem
        write_mem(rname(mem.base), mem.disp, _get(state, rname(ops[0])))
        state.pc += insn.size
        return state

    if m == "b" and len(ops) == 1 and ops[0].type == ARM64_OP_IMM:
        state.pc = int(ops[0].imm)
        return state

    if m == "cbz" and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
        reg_is_zero = (_get(state, rname(ops[0])) == 0)
        if reg_is_zero:
            state.pc = insn.address + int(ops[1].imm)
        else:
            state.pc += insn.size
        return state

    if m == "bl" and len(ops) == 1 and ops[0].type == ARM64_OP_IMM:
        next_pc = insn.address + insn.size
        _set(state, "x30", next_pc)
        state.pc = int(ops[0].imm)
        state.flags["_depth"] = int(state.flags.get("_depth", 0)) + 1
        return state

    if m == "ret":
        lr = _get(state, "x30")
        state.pc = lr
        depth = int(state.flags.get("_depth", 0)) - 1
        state.flags["_depth"] = max(depth, 0)
        if state.flags["_depth"] == 0:
            state.flags["_halt"] = True
        return state

    state.pc += insn.size
    return state

from backend.ir import (
    IRNop, IRMovImm, IRMovReg, IRAdd, IRSub, IRLoad, IRStore,
    IRCmp, IRJmp, IRJe
)

def decode_to_ir(instr_bytes: bytes, state):
    code = instr_bytes[state.pc:]
    insn = next(_md.disasm(code, state.pc))
    m, ops = insn.mnemonic, insn.operands
    size = insn.size
    ir = []

    def rname(op_or_id):
        if isinstance(op_or_id, int):
            return insn.reg_name(op_or_id)
        return insn.reg_name(op_or_id.reg)

    if m == "nop":
        ir = [IRNop()]

    elif m.startswith("mov") and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        if ops[1].type == ARM64_OP_IMM:
            ir = [IRMovImm(rname(ops[0]), int(ops[1].imm))]
        elif ops[1].type == ARM64_OP_REG:
            ir = [IRMovReg(rname(ops[0]), rname(ops[1]))]

    elif m == "add" and len(ops) == 3 and ops[0].type == ARM64_OP_REG:
        if ops[2].type == ARM64_OP_IMM:
            ir = [IRAdd(rname(ops[0]), rname(ops[1]), int(ops[2].imm))]
        else:
            ir = [IRAdd(rname(ops[0]), rname(ops[1]), rname(ops[2]))]

    elif m in ("sub", "subs") and len(ops) == 3 and ops[0].type == ARM64_OP_REG:
        if ops[2].type == ARM64_OP_IMM:
            ir = [IRSub(rname(ops[0]), rname(ops[1]), int(ops[2].imm))]
        else:
            ir = [IRSub(rname(ops[0]), rname(ops[1]), rname(ops[2]))]
        if m == "subs":
            ir.append(IRCmp(rname(ops[0]), 0))

    elif m == "cmp" and len(ops) == 2 and ops[0].type == ARM64_OP_REG:
        right = (int(ops[1].imm) if ops[1].type == ARM64_OP_IMM else rname(ops[1]))
        ir = [IRCmp(rname(ops[0]), right)]

    elif m == "ldr" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
        mem = ops[1].mem
        ir = [IRLoad(rname(ops[0]), base=rname(mem.base), disp=mem.disp)]

    elif m == "str" and len(ops) == 2 and ops[1].type == ARM64_OP_MEM:
        mem = ops[1].mem
        ir = [IRStore(rname(ops[0]), base=rname(mem.base), disp=mem.disp)]

    elif m == "b" and len(ops) == 1 and ops[0].type == ARM64_OP_IMM:
        ir = [IRJmp(int(ops[0].imm))]

    elif m == "cbz" and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
        ir = [IRCmp(rname(ops[0]), 0), IRJe(int(ops[1].imm))]

    else:
        ir = [IRNop()]

    return ir, size
