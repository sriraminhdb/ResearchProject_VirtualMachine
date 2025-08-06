import pytest
from backend.orchestrator import run_bytes

def test_run_bytes_x86():
    # Three x86 NOPs (0x90), each 1 byte
    mem = b'\x90\x90\x90'
    state = run_bytes(mem, 'x86')
    assert state.pc == 3
    assert state.registers == {}

def test_run_bytes_arm():
    # Two ARM64 NOPs (0x1f2003d5), each 4 bytes
    mem = bytes.fromhex('1f2003d5') * 2
    state = run_bytes(mem, 'arm')
    assert state.pc == 8
    assert state.registers == {}

@pytest.mark.parametrize("sequence,isa,expected_pc", [
    (b'\x90\x90', 'x86', 2),                     # 2 x86 NOPs
    (bytes.fromhex('1f2003d5')*3, 'arm', 12),     # 3 ARM NOPs
])
def test_run_bytes_param(sequence, isa, expected_pc):
    state = run_bytes(sequence, isa)
    assert state.pc == expected_pc