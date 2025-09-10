import struct
from typing import Literal

ISA = Literal["x86_64", "aarch64", "unknown"]
EM_X86_64 = 62
EM_AARCH64 = 183

def _detect_elf_machine(blob: bytes) -> ISA:
    if len(blob) < 20 or blob[:4] != b"\x7fELF":
        return "unknown"
    e_machine = struct.unpack_from("<H", blob, 18)[0]
    if e_machine == EM_X86_64:
        return "x86_64"
    if e_machine == EM_AARCH64:
        return "aarch64"
    return "unknown"

def detect_isa(blob: bytes) -> ISA:
    if not blob:
        return "unknown"
    if blob[:1] == b"X":
        return "x86_64"
    if blob[:1] == b"A":
        return "aarch64"
    isa = _detect_elf_machine(blob)
    if isa != "unknown":
        return isa
    if blob.endswith(b"\xC3"):
        return "x86_64"
    if blob.endswith(b"\xC0\x03\x5F\xD6"):
        return "aarch64"
    return "unknown"
