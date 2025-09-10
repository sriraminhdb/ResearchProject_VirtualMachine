from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class VMState:
    memory: bytes | bytearray = b""
    pc: int = 0
    registers: Dict[str, int] = field(default_factory=dict)
    flags: Dict[str, Any] = field(default_factory=lambda: {"ZF": False})

    def __post_init__(self) -> None:
        if not isinstance(self.memory, bytearray):
            self.memory = bytearray(self.memory)
