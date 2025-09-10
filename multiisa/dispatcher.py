# multiisa/dispatcher.py
from __future__ import annotations

from typing import Dict
from backend.orchestrator import VMState, run_bytes


def _ensure(mem: bytearray, length: int) -> None:
    if length < 0:
        return
    if length > len(mem):
        mem.extend(b"\x00" * (length - len(mem)))


def _prepare_x86_chunk(st: VMState, code_end: int) -> None:
    rsp = int(st.registers.get("rsp", 4096))
    new_rsp = rsp - 8
    _ensure(st.memory, new_rsp + 8)
    st.memory[new_rsp:new_rsp + 8] = int(code_end).to_bytes(8, "little")
    st.registers["rsp"] = new_rsp


def _prepare_arm_chunk(st: VMState, code_end: int) -> None:
    st.registers["x30"] = int(code_end)


def _normalize_isa(isa: str) -> str:
    isa_l = isa.lower()
    if isa_l in ("x86_64", "x86"):
        return "x86"
    if isa_l in ("arm64", "aarch64", "arm"):
        return "arm"
    return isa_l


def dispatch_chunk(isa: str, code: bytes, regs: Dict[str, int], *, use_llvm: bool = False) -> Dict[str, int]:
    isa = _normalize_isa(isa)
    st = VMState(memory=bytearray(code), registers=dict(regs), pc=0)
    code_end = len(code)

    if isa == "x86":
        _prepare_x86_chunk(st, code_end)
    elif isa == "arm":
        _prepare_arm_chunk(st, code_end)
    else:
        raise ValueError(f"Unsupported ISA: {isa}")

    run_bytes(code, isa=isa, use_llvm=use_llvm, state=st)
    return dict(st.registers)
