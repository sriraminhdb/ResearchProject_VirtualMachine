import pytest
from backend.backends.x86 import step as x86_step
from backend.orchestrator import VMState, run_bytes

def run_once(hexcode, regs=None, pc=0, flags=None):
    state = VMState(
        memory=bytes.fromhex(hexcode),
        registers=regs or {},
        pc=pc
    )
    if flags:
        state.flags.update(flags)
    return x86_step(state.memory, state)

def test_jmp_forward():
    # JMP +2 over next NOP: E9 02 00 00 00; 90
    new = run_once("e90200000090")
    assert new.pc == 7

def test_mov_load_store():
    # MOV [RCX], RAX → 48 89 01
    s2 = run_once(
        "488901",
        regs={'rax': 0xdeadbeefcafebabe, 'rcx': 8}
    )
    # memory at  8..16 should contain that 8-byte value
    assert int.from_bytes(s2.memory[8:16], 'little') == 0xdeadbeefcafebabe

def test_cmp_je():
    # Sequence: CMP RAX,5; JE +7; MOV RBX,1; MOV RBX,2
    code = bytes.fromhex(
        "48 83 F8 05"            # cmp rax, 5
      + "74 07"                  # je +7
      + "48 C7 C3 01 00 00 00"   # mov rbx, 1
      + "48 C7 C3 02 00 00 00"   # mov rbx, 2
    .replace(" ", ""))

    # Manually step through, injecting rax=5
    from backend.backends.x86 import step as x86_step
    state = VMState(memory=code, registers={'rax': 5}, pc=0)
    state = x86_step(state.memory, state)  # cmp → sets ZF
    state = x86_step(state.memory, state)  # je  → branches over mov rbx,1
    state = x86_step(state.memory, state)  # mov rbx,2
    
    # Verify RBX is set to 2 and PC is at end of instruction
    assert state.registers.get('rbx') == 2
    assert state.pc == 20  # 4 + 2 + 7 + 7 = 20 bytes