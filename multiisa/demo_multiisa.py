from .orchestrator import run_program

X_SET_RBX_RDX = bytes.fromhex("48 C7 C3 2A 00 00 00 48 C7 C2 09 00 00 00 C3")
X_INC_RBX = bytes.fromhex("48 FF C3 C3")
A_SET_X1_X2 = bytes.fromhex("41 05 80 D2 22 01 80 D2 C0 03 5F D6")
A_ADD2_X1   = bytes.fromhex("21 08 00 91 C0 03 5F D6")

chunks = [
    b"X" + X_SET_RBX_RDX,
    b"A" + A_SET_X1_X2,
    b"X" + X_INC_RBX,
    b"A" + A_ADD2_X1,
]

regs0 = {"rbx": 0, "rdx": 0, "x1": 0, "x2": 0}
final_regs, metrics = run_program(chunks, regs0)

print(metrics.report_text())
print("\nFinal registers:")
for k in sorted(final_regs):
    print(f"  {k} = {final_regs[k]}")
