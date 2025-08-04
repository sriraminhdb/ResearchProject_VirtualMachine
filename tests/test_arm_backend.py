import pytest
from backend.backends.arm import step as arm_step
from backend.orchestrator import VMState

def test_mov_imm(tmp_path):
    # MOV X0, #5  → bytes.fromhex('a00080d2')
    code = bytes.fromhex('a00080d2')
    state = VMState(memory=code, registers={}, pc=0)
    new = arm_step(state.memory, state)
    assert new.pc == 4
    assert new.registers.get('x0') == 5

def test_add_reg(tmp_path):
    # ADD X0, X0, X1 → bytes.fromhex('0000018b')
    code = bytes.fromhex('0000018b')
    state = VMState(memory=code, registers={'x0': 3, 'x1': 4}, pc=0)
    new = arm_step(state.memory, state)
    assert new.pc == 4
    assert new.registers.get('x0') == 7
