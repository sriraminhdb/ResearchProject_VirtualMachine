from __future__ import annotations
from typing import Dict, List, Tuple, Any
import ctypes

from llvmlite import ir, binding as llvm

from backend.core.ir import (
    IROp, NOP, MOV, ADD, SUB, CMP, JE, JMP, CBZ, LOAD, STORE,
)

llvm.initialize()
llvm.initialize_native_target()
llvm.initialize_native_asmprinter()

_engine = None
_tm = None

CacheKey   = Tuple[str, int]
CacheEntry = Tuple[Any, Dict[str, int]]
_cache: Dict[CacheKey, CacheEntry] = {}

_stats = {
    "compile_ms_total": 0.0,
    "compiled_blocks": 0,
    "cache_hits": 0,
    "cache_misses": 0,
}

def cache_stats():
    """Return a snapshot of current JIT stats."""
    return dict(_stats)

def _note_hit():
    _stats["cache_hits"] += 1

def _note_miss():
    _stats["cache_misses"] += 1

def _note_compile(dt_ms: float):
    _stats["compile_ms_total"] += float(dt_ms)
    _stats["compiled_blocks"] += 1

def _get_engine():
    global _engine, _tm
    if _engine is not None:
        return _engine, _tm
    target = llvm.Target.from_default_triple()
    _tm = target.create_target_machine()
    backing_mod = llvm.parse_assembly("")
    _engine = llvm.create_mcjit_compiler(backing_mod, _tm)
    return _engine, _tm


def _get_regs_dict(state) -> Dict[str, int]:
    """Support either state.registers or state.regs; create registers if missing."""
    d = getattr(state, "registers", None)
    if isinstance(d, dict):
        return d
    d = getattr(state, "regs", None)
    if isinstance(d, dict):
        return d
    d = {}
    setattr(state, "registers", d)
    return d

def _reg_index_for_ops(ops: List[IROp]) -> Dict[str, int]:
    regs: Dict[str, int] = {}

    def use(r: str | None):
        if not r:
            return
        if r not in regs:
            regs[r] = len(regs)

    for op in ops:
        if isinstance(op, MOV):
            use(op.dst); use(op.src_reg)
        elif isinstance(op, ADD):
            use(op.dst); use(op.a); use(op.b_reg)
        elif isinstance(op, SUB):
            use(op.dst); use(op.a); use(op.b_reg)
        elif isinstance(op, CMP):
            use(op.a_reg); use(op.b_reg)
        elif isinstance(op, CBZ):
            use(op.reg)
        elif isinstance(op, LOAD):
            use(op.dst); use(op.base)
        elif isinstance(op, STORE):
            use(op.src); use(op.base)
    return regs

def _gep_i64(builder: ir.IRBuilder, base_ptr: ir.Value, idx: int):
    return builder.gep(base_ptr, [ir.Constant(ir.IntType(32), idx)])

def can_jit(ops: List[IROp]) -> bool:
    """Small but meaningful subset."""
    return all(isinstance(op, (NOP, MOV, ADD, SUB, CMP, JE, JMP, CBZ, LOAD, STORE)) for op in ops)

def _build_function(ir_ops: List[IROp], reg_map: Dict[str, int]) -> Tuple[ir.Function, ir.Module]:
    """
    Emit function:
        void run(i64* regs, i8* mem, i64* pc, i64* zf)
    """
    i64 = ir.IntType(64)
    i8  = ir.IntType(8)
    p_i64 = i64.as_pointer()
    p_i8  = i8.as_pointer()

    mod = ir.Module(name="vmblock")
    fn_ty = ir.FunctionType(ir.VoidType(), [p_i64, p_i8, p_i64, p_i64])
    fn = ir.Function(mod, fn_ty, name="run")
    regs_ptr, mem_ptr, pc_ptr, zf_ptr = fn.args
    regs_ptr.name = "regs"; mem_ptr.name = "mem"; pc_ptr.name = "pc"; zf_ptr.name = "zf"

    entry = fn.append_basic_block("entry")
    builder = ir.IRBuilder(entry)

    def load_pc():
        return builder.load(pc_ptr, name="pc_val")

    def store_pc(v):
        builder.store(v, pc_ptr)

    def inc_pc(sz: int):
        store_pc(builder.add(load_pc(), ir.Constant(i64, sz)))

    def set_zf_from_cmp(lhs, rhs):
        eq = builder.icmp_unsigned("==", lhs, rhs)
        builder.store(builder.zext(eq, i64), zf_ptr)

    def load_reg(name: str):
        slot = _gep_i64(builder, regs_ptr, reg_map[name])
        return builder.load(slot)

    def store_reg(name: str, val):
        slot = _gep_i64(builder, regs_ptr, reg_map[name])
        builder.store(val, slot)

    def load_mem_q(addr64):
        off_ptr = builder.gep(mem_ptr, [addr64])
        qptr    = builder.bitcast(off_ptr, p_i64)
        return builder.load(qptr, align=1)

    def store_mem_q(addr64, val64):
        off_ptr = builder.gep(mem_ptr, [addr64])
        qptr    = builder.bitcast(off_ptr, p_i64)
        builder.store(val64, qptr, align=1)

    for op in ir_ops:
        if isinstance(op, NOP):
            inc_pc(op.size)

        elif isinstance(op, MOV):
            v = load_reg(op.src_reg) if op.src_reg is not None \
                else ir.Constant(i64, int(op.src_imm or 0) & ((1<<64)-1))
            store_reg(op.dst, v)
            inc_pc(op.size)

        elif isinstance(op, ADD):
            a = load_reg(op.a)
            b = load_reg(op.b_reg) if op.b_reg is not None \
                else ir.Constant(i64, int(op.b_imm or 0) & ((1<<64)-1))
            res = builder.add(a, b)
            store_reg(op.dst, res)
            if op.set_flags: set_zf_from_cmp(res, ir.Constant(i64, 0))
            inc_pc(op.size)

        elif isinstance(op, SUB):
            a = load_reg(op.a)
            b = load_reg(op.b_reg) if op.b_reg is not None \
                else ir.Constant(i64, int(op.b_imm or 0) & ((1<<64)-1))
            res = builder.sub(a, b)
            store_reg(op.dst, res)
            if op.set_flags: set_zf_from_cmp(res, ir.Constant(i64, 0))
            inc_pc(op.size)

        elif isinstance(op, CMP):
            a = load_reg(op.a_reg)
            b = load_reg(op.b_reg) if op.b_reg is not None \
                else ir.Constant(i64, int(op.b_imm or 0) & ((1<<64)-1))
            res = builder.sub(a, b)
            set_zf_from_cmp(res, ir.Constant(i64, 0))
            inc_pc(op.size)

        elif isinstance(op, JE):
            zf  = builder.load(zf_ptr)
            cond = builder.icmp_unsigned("!=", zf, ir.Constant(i64, 0))
            then_bb = fn.append_basic_block("je_then")
            else_bb = fn.append_basic_block("je_else")
            cont_bb = fn.append_basic_block("je_cont")
            builder.cbranch(cond, then_bb, else_bb)

            builder.position_at_end(then_bb)
            store_pc(ir.Constant(i64, int(op.target))); builder.branch(cont_bb)

            builder.position_at_end(else_bb)
            inc_pc(op.size); builder.branch(cont_bb)

            builder.position_at_end(cont_bb)

        elif isinstance(op, JMP):
            store_pc(ir.Constant(i64, int(op.target)))

        elif isinstance(op, CBZ):
            r = load_reg(op.reg)
            cond = builder.icmp_unsigned("==", r, ir.Constant(i64, 0))
            then_bb = fn.append_basic_block("cbz_then")
            else_bb = fn.append_basic_block("cbz_else")
            cont_bb = fn.append_basic_block("cbz_cont")
            builder.cbranch(cond, then_bb, else_bb)

            builder.position_at_end(then_bb)
            store_pc(ir.Constant(i64, int(op.target))); builder.branch(cont_bb)

            builder.position_at_end(else_bb)
            inc_pc(op.size); builder.branch(cont_bb)

            builder.position_at_end(cont_bb)

        elif isinstance(op, LOAD):
            base = load_reg(op.base)
            addr = builder.add(base, ir.Constant(i64, int(op.disp) & ((1<<64)-1)))
            q = load_mem_q(addr)
            store_reg(op.dst, q)
            inc_pc(op.size)

        elif isinstance(op, STORE):
            base = load_reg(op.base)
            addr = builder.add(base, ir.Constant(i64, int(op.disp) & ((1<<64)-1)))
            v = load_reg(op.src)
            store_mem_q(addr, v)
            inc_pc(op.size)

        else:
            inc_pc(getattr(op, "size", 1))

    builder.ret_void()
    return fn, mod

def _compile(ir_ops: List[IROp], key: CacheKey) -> None:
    eng, _tm = _get_engine()
    reg_map = _reg_index_for_ops(ir_ops)
    _, mod = _build_function(ir_ops, reg_map)
    llvm_mod = llvm.parse_assembly(str(mod))
    llvm_mod.verify()
    eng.add_module(llvm_mod)
    eng.finalize_object()
    ptr = eng.get_function_address("run")
    cfunctype = ctypes.CFUNCTYPE(None,
                                 ctypes.POINTER(ctypes.c_uint64),
                                 ctypes.POINTER(ctypes.c_uint8),
                                 ctypes.POINTER(ctypes.c_uint64),
                                 ctypes.POINTER(ctypes.c_uint64))
    cfunc = cfunctype(ptr)
    _cache[key] = (cfunc, reg_map)

def run_or_compile(state, ir_ops: List[IROp], isa: str):
    import time
    key: CacheKey = (isa, state.pc)
    if key not in _cache:
        _note_miss()
        t0 = time.perf_counter()
        _compile(ir_ops, key)
        dt_ms = (time.perf_counter() - t0) * 1000.0
        _note_compile(dt_ms)
        if hasattr(getattr(state, "metrics", None), "add_jit_compile"):
            state.metrics.add_jit_compile(dt_ms)
    else:
        _note_hit()
        if hasattr(getattr(state, "metrics", None), "inc_jit_hit"):
            state.metrics.inc_jit_hit()

    cfunc, reg_map = _cache[key]

    n = max(reg_map.values(), default=-1) + 1
    RegArray = ctypes.c_uint64 * (n if n > 0 else 1)
    regs_arr = RegArray()
    for name, idx in reg_map.items():
        regs_arr[idx] = int(state.registers.get(name, 0)) & ((1<<64)-1)

    MemArray = (ctypes.c_uint8 * len(state.memory))
    mem_view = MemArray.from_buffer(state.memory)

    pc_val = ctypes.c_uint64(state.pc)
    zf_val = ctypes.c_uint64(1 if state.flags.get("ZF", False) else 0)

    cfunc(regs_arr, mem_view, ctypes.byref(pc_val), ctypes.byref(zf_val))

    for name, idx in reg_map.items():
        state.registers[name] = int(regs_arr[idx]) & ((1<<64)-1)
    state.pc = int(pc_val.value)
    state.flags["ZF"] = (zf_val.value != 0)
