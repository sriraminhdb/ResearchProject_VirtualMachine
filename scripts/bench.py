import argparse, time
from backend.orchestrator import run_bytes

def bench_loop(name, payload, isa, iters):
    start = time.time()
    total = 0
    for _ in range(iters):
        st = run_bytes(payload, isa)
        total += st.pc
    elapsed = time.time() - start
    ips = (len(payload) * iters) / elapsed if elapsed > 0 else 0
    print(f"{name}: {int(ips):>6} instr/s over {elapsed:.3f}s")
    return elapsed

def make_nops(n, isa):
    if isa == "x86":
        return bytes([0x90]) * n
    return bytes.fromhex("1F2003D5") * n

def make_alu_mix_x86(n):
    return bytes.fromhex("48 31 C0 48 83 C0 01 48 83 E8 01 90") * n

def make_alu_mix_arm(n):
    return bytes.fromhex("E0 03 00 AA 00 04 00 91 00 04 00 D1 1F 20 03 D5") * n

def make_mem_stride_x86(n):
    return bytes.fromhex("48 8B 04 24 48 89 04 24 48 83 C4 08 48 83 EC 08") * n

def make_mem_stride_arm(n):
    return bytes.fromhex("E0 03 40 F9 E0 03 00 F9 FF 43 00 91 FF 43 00 D1") * n

def switch_blob():
    return bytes.fromhex(
        "48 C7 C3 01 00 00 00 EB 07" + "90"*7 + "41 05 80 D2 1F 20 03 D5"
    )

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--nops", type=int, default=1000)
    ap.add_argument("--iters", type=int, default=100)
    args = ap.parse_args()

    print("=== Microbench ===")
    t1 = bench_loop("x86 NOPs", make_nops(args.nops, "x86"), "x86", args.iters)
    t2 = bench_loop("ARM NOPs", make_nops(args.nops, "arm"), "arm", args.iters)

    print("\n=== ALU Mix ===")
    bench_loop("x86 ALU", make_alu_mix_x86(200), "x86", args.iters)
    bench_loop("ARM ALU", make_alu_mix_arm(200), "arm", args.iters)

    print("\n=== Mem Stride ===")
    bench_loop("x86 MEM", make_mem_stride_x86(200), "x86", args.iters)
    bench_loop("ARM MEM", make_mem_stride_arm(200), "arm", args.iters)

    print("\n=== Switch Latency ===")
    laps = args.iters
    blob = switch_blob()
    start = time.time()
    for _ in range(laps):
        run_bytes(blob, "auto")
    sw = time.time() - start
    print(f"Switch latency ~ {sw/laps*1e6:.2f} µs/switch  (total {sw:.3f}s for {laps} laps)")
