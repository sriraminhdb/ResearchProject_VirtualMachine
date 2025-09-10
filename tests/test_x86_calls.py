import pytest
from backend.orchestrator import VMState, run_bytes

def test_push_pop_cross_regs():
    # rax <- 0x1122334455667788; push rax; pop rbx
    code = bytes.fromhex(
        "48 C7 C0 88 77 66 55"  # mov rax,0x55667788 (low 32)
        "48 B8 88 77 66 55 44 33 22 11"  # mov rax,0x1122334455667788
        "50"                    # push rax
        "5B"                    # pop rbx
    )
    final = run_bytes(code, 'x86')
    assert final.registers.get('rbx') == 0x1122334455667788

def test_call_ret_sets_rbx_in_function():
    # call +10 -> function at 0x0 + 5 + 10 = 0xF (15)
    # function: mov rbx,7 ; ret
    code = bytes.fromhex(
        "E8 0A 00 00 00"            # 00: call +0x0A (-> 0x0F)
        "90"                        # 05: nop
        "90"                        # 06: nop
        "90"                        # 07: nop
        "90"                        # 08: nop
        "90"                        # 09: nop
        "90"                        # 0A: nop
        "90"                        # 0B: nop
        "90"                        # 0C: nop
        "90"                        # 0D: nop
        "90"                        # 0E: nop
        "48 C7 C3 07 00 00 00"      # 0F: mov rbx,7
        "C3"                        # 16: ret
    )
    final = run_bytes(code, 'x86')
    assert final.registers.get('rbx') == 7
    # rsp should be restored to stack top (allocated by orchestrator)
    assert final.registers['rsp'] == len(final.memory)
