from backend.isadetect import detect_isa
from backend.dispatcher import dispatch

class VMState:
    def __init__(self, memory: bytes, registers=None, pc: int = 0):
        self.memory = memory
        self.registers = registers or {}
        self.pc = pc

def run(binary_path: str):
    isa = detect_isa(binary_path)
    state = VMState(memory=b"")
    while True:
        instr_bytes = b""  # TODO: fetch bytes at state.pc
        state = dispatch(instr_bytes, state, isa)
        break
