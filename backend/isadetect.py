from __future__ import annotations
from typing import Union

EM_X86_64 = 62
EM_AARCH64 = 183

def _looks_like_elf(buf: bytes) -> bool:
    return len(buf) >= 20 and buf[:4] == b"\x7fELF"

def _elf_emachine_from_bytes(buf: bytes) -> int | None:
    if not _looks_like_elf(buf):
        return None
    return int.from_bytes(buf[18:20], "little")

def _heuristic_from_bytes(buf: bytes) -> str:
    head = buf[:16]
    if head[:4] in (b"\x1F\x20\x03\xD5", b"\x41\x05\x80\xD2"):
        return "arm"
    if head[:1] in {b"\x48", b"\x90", b"\xE9", b"\xEB", b"\xC3", b"\x55"}:
        return "x86"
    return "x86"

def detect(obj: Union[str, bytes, bytearray]) -> str:
    """
    Detect ISA from either:
      * a path to an ELF file (str), or
      * a raw bytes window (bytes/bytearray).
    Returns: 'x86' or 'arm'.
    """
    if isinstance(obj, (bytes, bytearray)):
        em = _elf_emachine_from_bytes(bytes(obj))
        if em == EM_X86_64:
            return "x86"
        if em == EM_AARCH64:
            return "arm"
        return _heuristic_from_bytes(bytes(obj))

    with open(obj, "rb") as f:
        hdr = f.read(64)
    em = _elf_emachine_from_bytes(hdr)
    if em == EM_X86_64:
        return "x86"
    if em == EM_AARCH64:
        return "arm"
    raise ValueError("Unsupported or invalid ELF e_machine")

detect_isa = detect
