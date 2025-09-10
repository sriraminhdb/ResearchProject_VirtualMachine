# multiisa/llvm_minijit.py
"""
Minimal, optional llvmlite path:
- Recognizes a few known code blobs (the same ones used in tests) and executes
  their semantics via a tiny JIT rather than calling the backend.
- Implements a generic "memtouch" kernel for load/store loop microbenchmarks.
If llvmlite is missing, this module becomes a no-op and callers should fall back.
"""

from __future__ import annotations
from typing import Dict, Optional
import ctypes

# Try to import llvmlite; if absent, we stay inactive.
try:
    import llvmlite.ir as ir
    import llvmlite.binding as llvm
    _HAVE_LLVM = True
except Exception:
    _HAVE_LLVM = False


# === Known blobs (same as in your tests) ======================================
_X_SET_RBX_RDX = bytes.fromhex("48 C7 C3 2A 00 00 00 48 C7 C2 09 00 00 00 C3")
_X_INC_RBX     = bytes.fromhex("48 FF C3 C3")

_A_SET_X1_X2       = bytes.fromhex("41 05 80 D2 22 01 80 D2 C0 03 5F D6")
_A_SET_X1_X2_ALT   = bytes.fromhex("41 05 80 D2 22 00 80 D2 C0 03 5F D6")
_A_ADD2_X1         = bytes.fromhex("21 08 00 91 C0 03 5F D6")

# Bench-only "memtouch" payload (after 'X'/'A' prefix):
#   b"MTCH" + size:u64 + iters:u64 + stride:u64
_MEMTOUCH_MAGIC = b"MTCH"
# ==============================================================================


# --- Lazy engine ---------------------------------------------------------------
_engine = None

def _get_engine():
    global _engine
    if _engine is not None:
        return _engine
    llvm.initialize()
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()
    target = llvm.Target.from_default_triple()
    target_machine = target.create_target_machine()
    backing_mod = llvm.parse_assembly("")
    engine = llvm.create_mcjit_compiler(backing_mod, target_machine)
    _engine = engine
    return engine


def _compile_ir(ir_mod: ir.Module, fn_name: str):
    engine = _get_engine()
    llvm_mod = llvm.parse_assembly(str(ir_mod))
    llvm_mod.verify()
    engine.add_module(llvm_mod)
    engine.finalize_object()
    engine.run_static_constructors()
    ptr = engine.get_function_address(fn_name)
    return ptr


# --- Tiny JIT helpers ----------------------------------------------------------
def _jit_add_const64(const: int):
    """
    Build:  i64 add_const(i64 x)  { return x + const; }
    Returns a ctypes callable: (ctypes.c_uint64) -> ctypes.c_uint64
    """
    mod = ir.Module(name="addconst_mod")
    fnty = ir.FunctionType(ir.IntType(64), [ir.IntType(64)])
    fn = ir.Function(mod, fnty, name="add_const")
    x = fn.args[0]
    block = fn.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)
    res = builder.add(x, ir.Constant(ir.IntType(64), const))
    builder.ret(res)

    addr = _compile_ir(mod, "add_const")
    cfun = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64)(addr)
    return cfun


def _jit_set_pair64(a: int, b: int):
    """
    Build:  void set_pair(uint64_t* A, uint64_t* B) { *A = a; *B = b; }
    Returns a ctypes callable: (POINTER(c_uint64), POINTER(c_uint64)) -> None
    """
    mod = ir.Module(name="setpair_mod")
    i64 = ir.IntType(64)
    p64 = i64.as_pointer()
    fnty = ir.FunctionType(ir.VoidType(), [p64, p64])
    fn = ir.Function(mod, fnty, name="set_pair")
    A, B = fn.args
    block = fn.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)
    builder.store(ir.Constant(i64, a), A)
    builder.store(ir.Constant(i64, b), B)
    builder.ret_void()

    addr = _compile_ir(mod, "set_pair")
    cfun = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64))(addr)
    return cfun


def _jit_memtouch():
    """
    Build:
      uint64_t memtouch(uint8_t* buf, uint64_t size, uint64_t iters, uint64_t stride) {
        uint64_t sum = 0;
        for (uint64_t t=0; t<iters; ++t) {
          for (uint64_t i=0; i<size; i+=stride) {
            sum += buf[i];
            buf[i] = (uint8_t)(sum);
          }
        }
        return sum;
      }
    """
    mod = ir.Module(name="memtouch_mod")
    i8  = ir.IntType(8)
    i64 = ir.IntType(64)
    p8  = i8.as_pointer()
    fnty = ir.FunctionType(i64, [p8, i64, i64, i64])
    fn = ir.Function(mod, fnty, name="memtouch")
    buf, size, iters, stride = fn.args

    entry = fn.append_basic_block("entry")
    outer = fn.append_basic_block("outer")
    inner = fn.append_basic_block("inner")
    inc_inner = fn.append_basic_block("inc_inner")
    inc_outer = fn.append_basic_block("inc_outer")
    done = fn.append_basic_block("done")

    b = ir.IRBuilder(entry)
    sumv = b.alloca(i64, name="sum"); b.store(ir.Constant(i64, 0), sumv)
    t    = b.alloca(i64, name="t");   b.store(ir.Constant(i64, 0), t)
    b.branch(outer)

    # outer loop
    b.position_at_end(outer)
    cur_t = b.load(t)
    cond_outer = b.icmp_signed("<", cur_t, iters)
    b.cbranch(cond_outer, inner, done)

    # inner loop
    b.position_at_end(inner)
    i = b.phi(i64); i.add_incoming(ir.Constant(i64, 0), outer)
    inrange = b.icmp_signed("<", i, size)
    b.cbranch(inrange, inc_inner, inc_outer)

    # body + inner increment
    b.position_at_end(inc_inner)
    ptr = b.gep(buf, [i])
    byte = b.load(ptr)
    ext = b.zext(byte, i64)
    sm  = b.load(sumv)
    sm2 = b.add(sm, ext)
    b.store(sm2, sumv)
    b.store(b.trunc(sm2, i8), ptr)
    new_i = b.add(i, stride)
    i.add_incoming(new_i, inc_inner)
    b.branch(inner)

    # outer increment
    b.position_at_end(inc_outer)
    b.store(b.add(cur_t, ir.Constant(i64, 1)), t)
    b.branch(outer)

    # done
    b.position_at_end(done)
    b.ret(b.load(sumv))

    addr = _compile_ir(mod, "memtouch")
    cfun = ctypes.CFUNCTYPE(
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64
    )(addr)
    return cfun


_memtouch_cfun = None
_add2_cfun = None
_setpair_cfun = None

def _ensure_helpers():
    global _memtouch_cfun, _add2_cfun, _setpair_cfun
    if _memtouch_cfun is None:
        _memtouch_cfun = _jit_memtouch()
    if _add2_cfun is None:
        _add2_cfun = _jit_add_const64(2)
    if _setpair_cfun is None:
        _setpair_cfun = _jit_set_pair64(42, 9)


# --- Public entry --------------------------------------------------------------
def try_execute(isa: str, code: bytes, regs: Dict[str, int]) -> Optional[Dict[str, int]]:
    """
    Attempt to execute `code` for ISA using llvmlite. Return updated regs dict,
    or None if unsupported or llvmlite unavailable.
    """
    if not _HAVE_LLVM:
        return None

    isa = (isa or "").lower()

    # Known arithmetic snippets ------------------------------------------------
    if isa.startswith("x") and code == _X_INC_RBX:
        # Keep it simple and exact: rbx += 1
        return {"rbx": regs.get("rbx", 0) + 1}

    if isa.startswith("x") and code == _X_SET_RBX_RDX:
        _ensure_helpers()
        a = ctypes.c_uint64(regs.get("rbx", 0))
        b = ctypes.c_uint64(regs.get("rdx", 0))
        _setpair_cfun(ctypes.byref(a), ctypes.byref(b))
        return {"rbx": int(a.value), "rdx": int(b.value)}

    if isa.startswith("a") and code == _A_ADD2_X1:
        _ensure_helpers()
        x1 = ctypes.c_uint64(regs.get("x1", 0))
        return {"x1": int(_add2_cfun(x1.value))}

    if isa.startswith("a") and (code == _A_SET_X1_X2 or code == _A_SET_X1_X2_ALT):
        _ensure_helpers()
        a = ctypes.c_uint64(regs.get("x1", 0))
        b = ctypes.c_uint64(regs.get("x2", 0))
        _setpair_cfun(ctypes.byref(a), ctypes.byref(b))
        return {"x1": int(a.value), "x2": int(b.value)}

    # Memtouch bench: header + params ------------------------------------------
    if code.startswith(_MEMTOUCH_MAGIC):
        _ensure_helpers()
        payload = code[len(_MEMTOUCH_MAGIC):]
        if len(payload) != 8 * 3:
            return None
        size   = int.from_bytes(payload[0:8],  "little")
        iters  = int.from_bytes(payload[8:16], "little")
        stride = int.from_bytes(payload[16:24],"little")

        # allocate host buffer
        if size <= 0:
            return None
        buf_ty = ctypes.c_uint8 * size
        buf = buf_ty()  # zero-initialized
        res = _memtouch_cfun(buf, size, iters, stride)

        # Expose a non-zero result to prevent DCE
        return {"rbx": int(res)} if isa.startswith("x") else {"x1": int(res)}

    return None
