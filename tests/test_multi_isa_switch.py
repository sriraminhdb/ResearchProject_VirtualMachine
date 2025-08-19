import json
import time
from backend.orchestrator import run_bytes, VMState

def make_x86_jmp_short(to_from_next):
    # EB imm8 (short jump); imm is from NEXT instruction address
    return bytes([0xEB, (to_from_next & 0xFF)])

def arm_b_imm32(target, pc):
    """
    Encode AArch64 B imm26 to reach 'target' from 'pc' (address of this instruction).
    Encoding: 0b000101 | imm26 (signed) ; imm26 = (target - pc) >> 2
    Returns 4 little-endian bytes.
    """
    diff = target - pc
    imm26 = (diff >> 2) & ((1 << 26) - 1)
    word = 0x14000000 | imm26
    return word.to_bytes(4, "little")

def test_multi_isa_auto_switch_once():
    """
    Layout:
      0x00: x86  mov rbx,1                      (7 bytes)
      0x07: x86  jmp +7 -> 0x10                 (2 bytes; 7 from 0x09 -> 0x10)
      0x10: ARM  movz x1,#42                    (0xD2800541 little endian)
      0x14: ARM  nop                            (0x1f2003d5)
      (halt via breakpoint at 0x14)
    We run with isa='auto' and a breakpoint at 0x14. Expect a switch x86 -> arm.
    """

    # x86: mov rbx,1 (48 C7 C3 01 00 00 00)
    x86_mov_rbx_1 = bytes.fromhex("48 C7 C3 01 00 00 00")
    jmp_to_0x10   = make_x86_jmp_short(0x10 - (0x07 + 2))  # from 0x09 -> 0x10 => 7

    # ARM: movz x1,#42 (0xD2800541) + nop (0xD503201F)
    arm_movz_x1_42 = bytes.fromhex("41 05 80 D2")
    arm_nop        = bytes.fromhex("1F 20 03 D5")

    blob = bytearray()
    blob += x86_mov_rbx_1         # 0x00..0x06
    blob += jmp_to_0x10           # 0x07..0x08
    blob += b"\x90" * (0x10 - len(blob))  # pad with x86 NOPs to 0x10
    blob += arm_movz_x1_42        # 0x10..0x13
    blob += arm_nop               # 0x14..0x17

    trace_log = []
    def tracer(tag, data):
        # Keep a minimal trace for assertions
        if tag == "on_switch":
            trace_log.append(("switch", data.get("from"), data.get("to"), data.get("pc")))

    # Break at 0x14 so we can assert right after entering ARM
    st = run_bytes(bytes(blob), 'auto', breakpoints={0x14}, trace=tracer)
    # We reached the breakpoint:
    assert st.pc == 0x14
    # Should have switched from x86 -> arm
    assert any(t[1] == "x86" and t[2] == "arm" for t in trace_log)
    # ARM code executed and set x1=42:
    assert st.registers.get("x1") == 42

def test_multi_isa_auto_two_switches():
    """
    Layout:
      0x00: x86 mov rbx,1
      0x07: x86 jmp +7 -> 0x10
      0x10: ARM nop
      0x14: ARM b -> 0x20 (back to x86 region)
      0x20: x86 mov rbx,9
    Expect: x86 -> arm -> x86 switches and rbx == 9 at the end.
    """
    x86_mov_rbx_1 = bytes.fromhex("48 C7 C3 01 00 00 00")
    jmp_to_0x10   = bytes.fromhex("EB 07")  # from 0x09 -> 0x10
    arm_nop       = bytes.fromhex("1F 20 03 D5")

    blob = bytearray()
    blob += x86_mov_rbx_1                # 0x00..0x06
    blob += jmp_to_0x10                  # 0x07..0x08
    blob += b"\x90" * (0x10 - len(blob)) # pad
    blob += arm_nop                      # 0x10..0x13
    # ARM b to 0x20; PC of b is 0x14:
    blob += arm_b_imm32(0x20, 0x14)      # 0x14..0x17
    # Pad to 0x20:
    blob += b"\x90" * (0x20 - len(blob))
    # x86: mov rbx,9
    blob += bytes.fromhex("48 C7 C3 09 00 00 00")  # 0x20..0x26

    trace_log = []
    def tracer(tag, data):
        if tag == "on_switch":
            trace_log.append((data.get("from"), data.get("to"), data.get("pc")))

    st = run_bytes(bytes(blob), 'auto', breakpoints={0x27}, trace=tracer)
    # Expect both directions observed:
    assert any(a=="x86" and b=="arm" for a,b,_ in trace_log)
    assert any(a=="arm" and b=="x86" for a,b,_ in trace_log)
    assert st.registers.get("rbx") == 9
