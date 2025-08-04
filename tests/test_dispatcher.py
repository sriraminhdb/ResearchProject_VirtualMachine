import pytest
from backend.dispatcher import dispatch
from backend.orchestrator import VMState

@pytest.mark.parametrize("opcode,isa,expected_pc", [
    (b"\x90",     "x86",  1),  # x86 NOP
    (bytes.fromhex("1f2003d5"), "arm", 4),  # ARM64 NOP
])
def test_dispatch_nop(tmp_path, opcode, isa, expected_pc):
    # Prepare a VMState with just the opcode in memory and PC=0
    state = VMState(memory=opcode, registers={}, pc=0)
    new_state = dispatch(opcode, state, isa)
    assert new_state.pc == expected_pc