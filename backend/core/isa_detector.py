from __future__ import annotations
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

_md_x86 = Cs(CS_ARCH_X86, CS_MODE_64); _md_x86.detail = False
_md_a64 = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); _md_a64.detail = False

def _can_decode(md, buf, pc, span):
    try:
        _ = next(md.disasm(buf[pc:pc+span], pc))
        return True
    except StopIteration:
        return False

def detect(buf: bytes, pc: int, hint: str | None = None) -> str:
    arm_nop = (pc + 4 <= len(buf)) and (buf[pc:pc+4] == b"\x1F\x20\x03\xD5")

    ok_x86 = _can_decode(_md_x86, buf, pc, 15)
    ok_a64 = (pc + 4 <= len(buf)) and _can_decode(_md_a64, buf, pc, 4)

    if arm_nop:
        return "arm"

    if ok_x86 and not ok_a64:
        return "x86"
    if ok_a64 and not ok_x86:
        return "arm"

    if ok_x86 and ok_a64:
        return "arm" if (pc % 4) == 0 else "x86"

    return hint if hint in ("x86", "arm") else "x86"
