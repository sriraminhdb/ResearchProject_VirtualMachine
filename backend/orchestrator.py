from backend.isadetect import detect_isa
from backend.dispatcher import dispatch

class VMState:
    def __init__(self, memory: bytes, registers=None, pc: int = 0):
        # Use mutable memory buffer
        self.memory = bytearray(memory)
        self.registers = registers or {}
        self.pc = pc
        # Flags for conditional logic
        self.flags = {'ZF': False}

def run_bytes(memory: bytes, isa: str) -> VMState:
    """
    Execute instructions in `memory` for the given ISA,
    returning the final VMState.
    """
    state = VMState(memory=memory)
    # Keep executing until PC walks off the end of the real memory buffer
    while state.pc < len(state.memory):
        # Always pass the full memory; each backend will decode at state.pc
        state = dispatch(state.memory, state, isa)
    return state

def run(binary_path: str) -> VMState:
    """
    Detect ISA for the given ELF file at `binary_path`,
    load its bytes, and execute to completion.
    """
    isa = detect_isa(binary_path)
    with open(binary_path, 'rb') as f:
        mem = f.read()
    return run_bytes(mem, isa)

def dispatch(instr_bytes: bytes, state, isa: str):
    if isa == "x86":
        from backend.backends.x86 import step as x86_step
        return x86_step(instr_bytes, state)
    elif isa == "arm":
        from backend.backends.arm import step as arm_step
        return arm_step(instr_bytes, state)
    else:
        raise ValueError(f"Unsupported ISA: {isa}")
