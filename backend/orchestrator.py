from __future__ import annotations
from typing import Any, Callable, Dict, Iterable, Optional, Set

from .state import VMState
from .dispatcher import dispatch as _dispatch
from . import isadetect as _isadetect


def _auto_detect_isa(state: VMState) -> str:
    """
    Detect ISA from the next few bytes in memory without touching the FS.
    Prefer a byte-aware detector if available; otherwise a small heuristic.
    """
    window = bytes(state.memory[state.pc:state.pc + 16])
    try:
        return _isadetect.detect(window)
    except Exception:
        if window[:4] in (b"\x1F\x20\x03\xD5", b"\x41\x05\x80\xD2"):
            return "arm"
        if window[:1] in {b"\x48", b"\x90", b"\xE9", b"\xEB", b"\xC3", b"\x55"}:
            return "x86"
        return "x86"


def run_bytes(
    code: bytes,
    isa: str = "auto",
    *,
    state: Optional[VMState] = None,
    registers: Optional[Dict[str, int]] = None,
    pc: Optional[int] = None,
    flags: Optional[Dict[str, Any]] = None,
    breakpoints: Optional[Iterable[int]] = None,
    trace: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    max_steps: Optional[int] = None,
    use_ir: bool = False,
    use_llvm: bool = False,
    **_ignored,
) -> VMState:
    created_here = state is None
    st = state or VMState(memory=code)

    if not isinstance(st.memory, bytearray):
        st.memory = bytearray(st.memory)
    if not st.memory:
        st.memory = bytearray(code)

    if registers:
        st.registers.update(registers)
    if pc is not None:
        st.pc = int(pc)
    if flags:
        st.flags.update(flags)

    st.code_end = len(st.memory)
    st.flags.setdefault("_halt", False)

    bps: Set[int] = set(int(x) for x in (breakpoints or []))
    steps_done = 0
    last_isa: Optional[str] = None

    if max_steps is None:
        max_steps = 1_000_000

    while True:
        if st.pc >= len(st.memory):
            break
        if bps and st.pc in bps:
            break
        if steps_done >= max_steps:
            break

        cur_isa = isa if isa != "auto" else _auto_detect_isa(st)
        if last_isa is not None and cur_isa != last_isa and trace:
            try:
                trace("on_switch", {"from": last_isa, "to": cur_isa, "pc": st.pc})
            except Exception:
                pass
        last_isa = cur_isa

        start_pc = st.pc
        _dispatch(bytes(st.memory[st.pc:]), st, cur_isa, use_ir=use_ir, use_llvm=use_llvm)
        steps_done += 1

        if st.pc == start_pc:
            raise RuntimeError(f"No progress made at PC=0x{start_pc:x} (isa={cur_isa})")

    return st
