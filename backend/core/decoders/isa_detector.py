from typing import Dict
from .decoders import x86_ir, arm_ir

Cache = Dict[int, str]

def detect(memory: bytes, pc: int, cache: Cache) -> str:
    if pc in cache:
        return cache[pc]
    chosen = None
    try_arm = (pc % 4 == 0) and (pc + 4 <= len(memory))

    if try_arm:
        try:
            size, _ = arm_ir.decode_one(memory, pc)
            if size == 4:
                chosen = "arm"
        except Exception:
            pass

    if chosen is None:
        try:
            size, _ = x86_ir.decode_one(memory, pc)
            if 1 <= size <= 15:
                chosen = "x86"
        except Exception:
            pass

    chosen = chosen or ("arm" if try_arm else "x86")
    cache[pc] = chosen
    return chosen
