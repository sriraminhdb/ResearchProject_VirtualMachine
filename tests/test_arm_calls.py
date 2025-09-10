import pytest
from backend.backends.arm import step as arm_step
from backend.orchestrator import VMState

def test_bl_ret_stepwise():
    # BL +4 (to PC=4), then RET at PC=4
    # BL imm: 0x94000001 -> little-endian "01 00 00 94"
    # RET:    0xD65F03C0 -> little-endian "C0 03 5F D6"
    code = bytes.fromhex("01 00 00 94" "C0 03 5F D6")

    s = VMState(memory=code, registers={}, pc=0)
    # Step 1: BL -> set x30=4 and pc=4
    s = arm_step(s.memory, s)
    assert s.registers.get('x30') == 4
    assert s.pc == 4

    # Step 2: RET -> pc := x30 (4). We stop here intentionally.
    s = arm_step(s.memory, s)
    assert s.pc == 4