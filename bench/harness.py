from __future__ import annotations
import argparse, csv, time
from typing import Dict, List, Tuple, Any

from backend.core.metrics import Metrics
from backend.orchestrator import VMState
from backend.dispatcher import dispatch as backend_dispatch

# Optional: JIT present?
try:
    import llvmlite_jit  # type: ignore
except Exception:
    llvmlite_jit = None  # type: ignore

from bench.ws_patterns import make_ws_loop_ir

# Keep your existing bytecode chunks (x86/arm)
X_SET_RBX_RDX = bytes.fromhex("48 C7 C3 2A 00 00 00 48 C7 C2 09 00 00 00 C3")
X_INC_RBX      = bytes.fromhex("48 FF C3 C3")
A_SET_X1_X2    = bytes.fromhex("41 05 80 D2 22 01 80 D2 C0 03 5F D6")
A_ADD2_X1      = bytes.fromhex("21 08 00 91 C0 03 5F D6")

def _row_default() -> Dict[str, Any]:
    return {
        "name": "",
        "total_ms": 0.0,
        "switches": 0,
        "total_instrs": 0,
        "ips": 0.0,
        "switch_latency_avg_ms": 0.0,  # placeholder if you later compute it
        "rss_min": 0, "rss_avg": 0, "rss_max": 0,
        "timeline_len": 0,
        # JIT columns
        "jit_compile_ms_total": 0.0,
        "jit_blocks_compiled": 0,
        "jit_cache_hits": 0,
        "jit_cache_misses": 0,
        # WS meta
        "ws_kb": 0,
        "stride": 0,
        "pattern": "",
        # Final registers
        "final_rbx": 0, "final_rdx": 0, "final_x1": 0, "final_x2": 0,
    }

def _run_bytes_once(isa: str, code: bytes, regs: Dict[str,int], *, use_llvm: bool, metrics: Metrics) -> Dict[str,int]:
    st = VMState(memory=code)
    st.metrics = metrics
    st.registers.update(regs)
    t1 = time.perf_counter()
    backend_dispatch(code, st, isa, use_llvm=use_llvm, use_ir=False, use_jit=False)
    dt = (time.perf_counter() - t1) * 1000.0
    metrics.total_ms += dt
    metrics.add_timeline_point(index=len(metrics.timeline)+1, isa=isa, bytes=len(code), ms=dt, regs_snapshot=dict(st.registers))
    return dict(st.registers)

def _scenario_alternating(n_cycles: int, *, use_llvm: bool) -> Tuple[Dict[str,int], Metrics]:
    chunks = []
    for _ in range(n_cycles):
        chunks.extend([
            ("x86", X_SET_RBX_RDX),
            ("arm", A_SET_X1_X2),
            ("x86", X_INC_RBX),
            ("arm", A_ADD2_X1),
        ])
    regs = {"rbx": 0, "rdx": 0, "x1": 0, "x2": 0}
    m = Metrics()
    prev = None
    for isa, code in chunks:
        regs = _run_bytes_once(isa, code, regs, use_llvm=use_llvm, metrics=m)
        if prev and prev != isa:
            m.switches += 1
        prev = isa
    return regs, m

def _scenario_noswitch(isa: str, n: int, *, use_llvm: bool) -> Tuple[Dict[str,int], Metrics]:
    regs = {"rbx": 0, "rdx": 0, "x1": 0, "x2": 0}
    m = Metrics()
    code_seq = {
        "x86": [X_SET_RBX_RDX, X_INC_RBX],
        "arm": [A_SET_X1_X2, A_ADD2_X1],
    }[isa]
    for _ in range(n):
        for code in code_seq:
            regs = _run_bytes_once(isa, code, regs, use_llvm=use_llvm, metrics=m)
    return regs, m

def _scenario_ws(pattern: str, ws_kb: int, stride: int, iters: int, *, use_llvm: bool) -> Tuple[Dict[str,int], Metrics]:
    """
    Working-set scenario driven by IR (read/write/rmw), repeating the same IR block
    'iters' times to amortize JIT compile cost and stress cache effects.
    """
    m = Metrics()
    ws_bytes = int(ws_kb) * 1024
    mem = bytearray(ws_bytes + 8*stride + 64)  # small pad
    st = VMState(memory=mem)
    st.metrics = m
    st.registers.update({"x1": 0, "x2": 0, "x3": 0, "x4": 0})

    # We generate a block that touches 'count' elements once; the outer loop repeats it.
    count = ws_bytes // 8
    ir_block = make_ws_loop_ir(base_reg="x1", idx_reg="x2", tmp_reg="x3", value_reg="x4",
                               start=0, count=count, stride=stride, mode=pattern)

    isa = "arm"  # arbitrary label (IR is ISA-agnostic)
    t0 = time.perf_counter()
    for _ in range(iters):
        if use_llvm and llvmlite_jit is not None and llvmlite_jit.can_jit(ir_block):
            llvmlite_jit.run_or_compile(st, ir_block, isa)
        else:
            # Fallback: interpret IR (requires backend.core.ir.exec_ir)
            from backend.core.ir import exec_ir  # type: ignore
            exec_ir(st, ir_block)
    dt_ms = (time.perf_counter() - t0) * 1000.0
    m.total_ms += dt_ms
    # write one timeline point to not leave it empty
    m.add_timeline_point(index=len(m.timeline)+1, isa=isa, bytes=len(ir_block), ms=dt_ms, regs_snapshot=dict(st.registers))

    regs = {"rbx": 0, "rdx": 0, "x1": int(st.registers.get("x1", 0)), "x2": int(st.registers.get("x2", 0))}
    return regs, m

def _fill_row_from(regs: Dict[str,int], m: Metrics, r: Dict[str,Any]):
    r["total_ms"] = round(m.total_ms, 3)
    r["switches"] = int(m.switches)
    r["timeline_len"] = len(m.timeline)
    r["total_instrs"] = r["timeline_len"]  # simple proxy
    r["ips"] = round((r["total_instrs"] / (r["total_ms"]/1000.0) if r["total_ms"] else 0.0), 2)
    # JIT stats (0 if not used)
    r["jit_compile_ms_total"] = round(m.jit_compile_ms_total, 3)
    r["jit_blocks_compiled"] = int(m.jit_blocks_compiled)
    r["jit_cache_hits"] = int(m.jit_cache_hits)
    r["jit_cache_misses"] = int(m.jit_cache_misses)
    # final regs
    r["final_rbx"] = int(regs.get("rbx", 0))
    r["final_rdx"] = int(regs.get("rdx", 0))
    r["final_x1"] = int(regs.get("x1", 0))
    r["final_x2"] = int(regs.get("x2", 0))

def _write_csv(rows: List[Dict[str,Any]], path: str):
    if not rows: return
    cols = list(rows[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

def _write_md(rows: List[Dict[str,Any]], path: str):
    if not rows: return
    cols = ["name","total_ms","switches","total_instrs","ips",
            "jit_blocks_compiled","jit_cache_hits","jit_cache_misses",
            "ws_kb","stride","pattern","timeline_len"]
    with open(path, "w") as f:
        f.write("# Multi-ISA VM Bench Report\n\n")
        f.write("| " + " | ".join(cols) + " |\n")
        f.write("|" + "|".join(["---"]*len(cols)) + "|\n")
        for r in rows:
            f.write("| " + " | ".join(str(r.get(k, "")) for k in cols) + " |\n")
        f.write("\n> Generated by `bench/harness.py`.\n")

def run_benches(out_csv: str, out_md: str, *, use_llvm: bool, ws_kb_list: List[int], ws_stride_list: List[int], ws_iters: int):
    rows: List[Dict[str,Any]] = []

    # Baselines (no switching)
    for n in (50, 500):
        regs, m = _scenario_noswitch("x86", n, use_llvm=use_llvm)
        row = _row_default(); row["name"] = f"x86_noswitch_{n}"
        _fill_row_from(regs, m, row); rows.append(row)

        regs, m = _scenario_noswitch("arm", n, use_llvm=use_llvm)
        row = _row_default(); row["name"] = f"arm_noswitch_{n}"
        _fill_row_from(regs, m, row); rows.append(row)

    # Alternating switch
    for n in (25, 250):
        regs, m = _scenario_alternating(n, use_llvm=use_llvm)
        row = _row_default(); row["name"] = f"alternating_{n}"
        _fill_row_from(regs, m, row); rows.append(row)

    # Working-set (cache) benches
    for ws_kb in ws_kb_list:
        for stride in ws_stride_list:
            for pattern in ("read", "write", "rmw"):
                regs, m = _scenario_ws(pattern, int(ws_kb), int(stride), int(ws_iters), use_llvm=use_llvm)
                row = _row_default(); row["name"] = f"ws_{pattern}_{ws_kb}kb_s{stride}"
                _fill_row_from(regs, m, row)
                row["ws_kb"] = int(ws_kb)
                row["stride"] = int(stride)
                row["pattern"] = pattern
                rows.append(row)

    _write_csv(rows, out_csv)
    _write_md(rows, out_md)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--use-llvm", action="store_true", help="enable llvmlite-based JIT where possible")
    ap.add_argument("--out-csv", default="bench_report.csv")
    ap.add_argument("--out-md",  default="bench_report.md")
    ap.add_argument("--ws-kb",   default="32,256,4096,65536", help="comma-separated KB sizes (working sets)")
    ap.add_argument("--ws-stride", default="1,8,64", help="comma-separated strides (elements of 8 bytes)")
    ap.add_argument("--ws-iters", type=int, default=50, help="times to repeat each IR block")
    args = ap.parse_args()

    ws_kb_list = [int(s) for s in str(args.ws_kb).split(",") if s.strip()]
    ws_stride_list = [int(s) for s in str(args.ws_stride).split(",") if s.strip()]

    run_benches(args.out_csv, args.out_md,
                use_llvm=args.use_llvm,
                ws_kb_list=ws_kb_list,
                ws_stride_list=ws_stride_list,
                ws_iters=args.ws_iters)

if __name__ == "__main__":
    main()