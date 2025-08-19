import pytest
from backend.orchestrator import run_bytes

def test_ir_arm_movz_basic():
    code = bytes.fromhex("41 00 80 D2")
    st = run_bytes(code, "arm", use_ir=True, max_steps=1)
    assert st.pc == 4
    assert st.registers.get("x1") == 2

def test_ir_arm_str_ldr_roundtrip():
    code = bytes.fromhex("20 00 00 F9 22 00 40 F9")
    st = run_bytes(
        code, "arm", use_ir=True, max_steps=2,
        registers={"x0": 0x1122, "x1": 0x100},
    )
    assert st.registers.get("x2") == 0x1122
    assert st.memory[0x100:0x108] == (0x1122).to_bytes(8, "little")
    assert st.pc == 8

def test_ir_x86_mov_imm64_into_rbx():
    code = bytes.fromhex("48 C7 C3 07 00 00 00")
    st = run_bytes(code, "x86", use_ir=True, max_steps=1)
    assert st.pc == 7
    assert st.registers.get("rbx") == 7

def test_ir_x86_jmp_short_skips_nops():
    code = bytes.fromhex("EB 02 90 90")
    st = run_bytes(code, "x86", use_ir=True, max_steps=1)
    assert st.pc == 4 

def test_ir_x86_cmp_je_then_mov():
    code = bytes.fromhex(
        "48 83 F8 05"            
        "74 07"                  
        "48 C7 C3 01 00 00 00"   
        "48 C7 C3 02 00 00 00"   
    )
    st = run_bytes(
        code,
        "x86",
        use_ir=True,
        max_steps=4,
        registers={"rax": 5},   
    )
    assert st.registers.get("rbx") == 2
    assert st.pc == 20
