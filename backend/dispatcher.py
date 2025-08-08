def dispatch(instr_bytes: bytes, state, isa: str):
    if isa == "x86":
        from backend.backends.x86 import step as x86_step
        return x86_step(instr_bytes, state)
    elif isa == "arm":
        from backend.backends.arm import step as arm_step
        return arm_step(instr_bytes, state)
    else:
        raise ValueError(f"Unsupported ISA: {isa}")