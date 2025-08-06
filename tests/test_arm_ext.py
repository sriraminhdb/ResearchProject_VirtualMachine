# tests/test_arm_ext.py

import pytest
from backend.backends.arm import step as arm_step
from backend.orchestrator import VMState, run_bytes

def run_once(hexcode, regs=None, pc=0, flags=None):
    state = VMState(memory=bytes.fromhex(hexcode), registers=regs or {}, pc=pc)
    if flags:
        state.flags.update(flags)
    return arm_step(state.memory, state)

def test_b_forward():
    new = run_once("01000014")
    assert new.pc == 4

def test_mov_imm():
    new = run_once("a00080d2")
    assert new.registers.get('x0') == 5
    assert new.pc == 4

def test_add_reg():
    new = run_once("0000018b", regs={'x0': 3, 'x1': 4})
    assert new.registers.get('x0') == 7
    assert new.pc == 4

def test_ldr_str():
    code = "200000f9" + "220040f9"
    state = VMState(memory=bytes.fromhex(code), registers={'x0': 0x1234, 'x1': 100}, pc=0)
    state = arm_step(state.memory, state)
    state = arm_step(state.memory, state)
    assert state.registers.get('x2') == 0x1234

def test_cmp_cbz():
    # Corrected sequence:
    #   MOV x0, #0
    #   SUBS x0, x0, #0
    #   CBZ x0, #8   (skip next instruction)
    #   MOV x1, #1
    #   MOV x1, #2
    seq = "000080d2" + "e00380e0" + "020000b4" + "210080d2" + "410080d2"
    final = run_bytes(bytes.fromhex(seq), 'arm')
    assert final.registers.get('x1') == 2