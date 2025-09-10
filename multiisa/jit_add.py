from typing import Callable

try:
    from llvmlite import binding as llvm
    from llvmlite import ir
    _HAVE_LLVM = True
except Exception:
    _HAVE_LLVM = False

def make_add_const_fn() -> Callable[[int, int], int]:
    if not _HAVE_LLVM:
        return lambda x, c: x + c

    llvm.initialize()
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()

    module = ir.Module(name="jit_add")
    fnty = ir.FunctionType(ir.IntType(64), [ir.IntType(64), ir.IntType(64)])
    fn = ir.Function(module, fnty, name="addc")
    block = fn.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)
    res = builder.add(fn.args[0], fn.args[1])
    builder.ret(res)

    tm = llvm.Target.from_default_triple().create_target_machine()
    engine = llvm.create_mcjit_compiler(llvm.parse_assembly(str(module)), tm)
    engine.finalize_object()

    addr = engine.get_function_address("addc")

    import ctypes
    cfunc = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)(addr)
    return lambda x, c: int(cfunc(x, c))

if __name__ == "__main__":
    f = make_add_const_fn()
    print("addc(40,2) =", f(40,2))
