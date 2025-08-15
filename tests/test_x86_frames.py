import pytest
from backend.orchestrator import VMState, run_bytes
from backend.backends.x86 import step as x86_step

def test_call_frame_local_store_load():
    """
    Caller calls function at 0x0F. Callee builds a frame, writes local at [rbp-8],
    loads into rbx, and returns. rbx must equal the 64-bit value.
    Layout (offsets in comments):
      00: E8 0A 00 00 00      call +0x0A  -> 0x0F
      05-0E:                  padding NOPs
      0F: 55                  push rbp
      10: 48 89 E5            mov rbp, rsp
      13: 48 83 EC 10         sub rsp, 0x10
      17: 48 B8 88 77 66 55 44 33 22 11  mov rax, 0x1122334455667788
      21: 48 89 45 F8         mov [rbp-8], rax
      25: 48 8B 5D F8         mov rbx, [rbp-8]
      29: C9                  leave
      2A: C3                  ret
    """
    code = bytes.fromhex(
        # caller
        "E8 0A 00 00 00"      # 00: call +0x0A -> 0x0F
        "90 90 90 90 90 90 90 90 90 90"  # 05-0E: nop x10
        # callee @ 0x0F
        "55"                  # 0F: push rbp
        "48 89 E5"            # 10: mov rbp, rsp
        "48 83 EC 10"         # 13: sub rsp, 0x10
        "48 B8 88 77 66 55 44 33 22 11"  # 17: movabs rax, 0x1122334455667788
        "48 89 45 F8"         # 21: mov [rbp-8], rax
        "48 8B 5D F8"         # 25: mov rbx, [rbp-8]
        "C9"                  # 29: leave
        "C3"                  # 2A: ret
    )
    final = run_bytes(code, 'x86')
    assert final.registers.get('rbx') == 0x1122334455667788

def test_ret_imm_pops_stack():
    """
    Validate ret imm16: rsp += 8 (return pop) + imm16.
    We step a single 'ret 16' and check pc and rsp adjustments.
    """
    code = bytes.fromhex("C2 10 00")  # ret 0x0010
    state = VMState(memory=code, pc=0)
    # Prepare a return address 3 (end of code) at current rsp slot
    top = state.registers['rsp']
    state.registers['rsp'] = top - 8  # make space so ret can read
    ret_addr = 3  # after 'ret 16'
    state.memory[state.registers['rsp']:state.registers['rsp']+8] = (ret_addr).to_bytes(8, 'little')

    state = x86_step(state.memory, state)
    assert state.pc == ret_addr
    # 8 for the return address + 16 from ret imm
    assert state.registers['rsp'] == (top - 8) + 8 + 16
