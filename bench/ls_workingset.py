from typing import List

X86_LOAD_STEP = bytes.fromhex("48 8B 04 1F 48 83 C3 08 C3")
ARM64_LOAD_STEP = bytes.fromhex("02 00 40 F9 21 08 00 91 C0 03 5F D6")

def make_ls_chunks(isa: str, ws_bytes: int, iters: int) -> List[bytes]:
    chunks: List[bytes] = []
    if isa in ("x86_64","x86"):
        prefix = b"X"
        step = X86_LOAD_STEP
        for _ in range(iters):
            chunks.append(prefix + step)
    else:
        prefix = b"A"
        step = ARM64_LOAD_STEP
        for _ in range(iters):
            chunks.append(prefix + step)
    return chunks
