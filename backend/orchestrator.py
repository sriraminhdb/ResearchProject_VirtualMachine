from dataclasses import dataclass

STACK_SIZE = 4096  # simple stack appended after code

@dataclass
class VMState:
    memory: bytearray
    registers: dict
    pc: int
    flags: dict
    code_end: int  # end of original code (before stack padding)

    def __init__(self, memory: bytes, registers=None, pc=0):
        # keep original code, remember its end, then append stack
        self.memory = bytearray(memory)
        self.code_end = len(self.memory)
        self.memory.extend(b"\x00" * STACK_SIZE)

        self.registers = dict(registers or {})
        top = len(self.memory)  # stack grows down from top
        self.registers.setdefault("rsp", top)  # x86-64
        self.registers.setdefault("sp",  top)  # AArch64

        self.pc = pc
        self.flags = {"ZF": False}

def run_bytes(memory: bytes, isa: str) -> VMState:
    from backend.dispatcher import dispatch
    state = VMState(memory=memory, pc=0)
    # Execute only within original code (don’t run into the zero-padded stack)
    while 0 <= state.pc < state.code_end:
        state = dispatch(state.memory, state, isa)
    return state
