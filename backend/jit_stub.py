def try_llvmlite_add(a: int, b: int):
    try:
        from llvmlite import ir, binding
    except Exception:
        return None

    binding.initialize()
    binding.initialize_native_target()
    binding.initialize_native_asmprinter()

    module = ir.Module(name="m")
    fnty = ir.FunctionType(ir.IntType(64), [ir.IntType(64), ir.IntType(64)])
    fn = ir.Function(module, fnty, name="add64")
    block = fn.append_basic_block(name="entry")
    builder = ir.IRBuilder(block)
    res = builder.add(fn.args[0], fn.args[1])
    builder.ret(res)

    target = binding.Target.from_default_triple()
    tm = target.create_target_machine()
    backing_mod = binding.parse_assembly(str(module))
    engine = binding.create_mcjit_compiler(backing_mod, tm)
    engine.finalize_object()

    func_ptr = engine.get_function_address("add64")
    import ctypes
    cfun = ctypes.CFUNCTYPE(ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64)(func_ptr)
    return cfun(a, b)
