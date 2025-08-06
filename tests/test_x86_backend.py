import pytest
from backend.backends.x86 import step as x86_step
from backend.orchestrator import VMState

@pytest.mark.parametrize("opcode,init_regs,expected_pc,expected_regs", [
    # MOV RAX,5
    ("48C7C005000000", {},            7, {"rax": 5}),
    # MOV RBX,RAX (rax starts at 10)
    ("4889C3",           {"rax": 10}, 3, {"rbx": 10}),
    # ADD RAX,2 (rax starts at 3)
    ("480502000000",     {"rax": 3},  6, {"rax": 5}),
    # ADD RAX,RBX (rax=2, rbx=3)
    ("4801D8",           {"rax": 2, "rbx": 3}, 3, {"rax": 5}),
])
def test_x86_mov_add(opcode, init_regs, expected_pc, expected_regs):
    code = bytes.fromhex(opcode)
    state = VMState(memory=code, registers=init_regs.copy(), pc=0)
    new_state = x86_step(state.memory, state)
    assert new_state.pc == expected_pc
    for reg, val in expected_regs.items():
        assert new_state.registers.get(reg) == val