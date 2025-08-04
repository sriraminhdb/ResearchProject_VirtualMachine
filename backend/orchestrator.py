from backend.isadetect import detect_isa
from backend.dispatcher import dispatch

class VMState:
    def __init__(self, memory: bytes, registers=None, pc: int = 0):
        self.memory = memory
        self.registers = registers or {}
        self.pc = pc

def run(binary_path: str):
    isa = detect_isa(binary_path)
    # TODO: load the binary file into a bytearray
    state = VMState(memory=b"")
    # TODO: implement fetch-decode-execute loop
    while True:
        instr_bytes = b""  # placeholder for fetched bytes
        state = dispatch(instr_bytes, state, isa)
        break  # remove once loop is implemented