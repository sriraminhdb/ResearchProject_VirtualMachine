def dispatch(instr_bytes: bytes, state, isa: str):
    """
    Dispatch instruction bytes to the appropriate ISA backend.
    """
    if isa == "x86":
        from backend.backends.x86 import step as x86_step
        # Always hand back the full memory and let step() slice via state.pc
        return x86_step(state.memory, state)
    elif isa == "arm":
        from backend.backends.arm import step as arm_step
        return arm_step(state.memory, state)
    else:
        raise ValueError(f"Unsupported ISA: {isa}")