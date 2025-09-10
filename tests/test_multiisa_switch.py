import pytest
from multiisa.orchestrator import run_program

X_SET_RBX_RDX = bytes.fromhex("48 C7 C3 2A 00 00 00 48 C7 C2 09 00 00 00 C3")
X_INC_RBX      = bytes.fromhex("48 FF C3 C3")
A_SET_X1_X2    = bytes.fromhex("41 05 80 D2 22 01 80 D2 C0 03 5F D6")
A_ADD2_X1      = bytes.fromhex("21 08 00 91 C0 03 5F D6")

@pytest.mark.parametrize("n_cycles", [1, 5, 20])
def test_alternating_switch(n_cycles):
    chunks = []
    for _ in range(n_cycles):
        chunks.extend([
            b"X" + X_SET_RBX_RDX,
            b"A" + A_SET_X1_X2,
            b"X" + X_INC_RBX,
            b"A" + A_ADD2_X1,
        ])

    regs0 = {"rbx": 0, "rdx": 0, "x1": 0, "x2": 0}
    final_regs, metrics = run_program(chunks, regs0)

    assert final_regs["rbx"] == 43
    assert final_regs["x1"] == 44
    assert final_regs["rdx"] == 9
    assert final_regs["x2"] == 9

    assert metrics.switches == len(chunks) - 1

    assert metrics.total_ms >= 0
    assert len(metrics.timeline) == len(chunks)
