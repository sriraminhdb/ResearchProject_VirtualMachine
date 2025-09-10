import sys, subprocess

def _run_cli_emit_tcg(isa: str, hex_bytes: str) -> str:
    """
    Run your CLI in --emit-tcg mode and return stdout.
    Fails the test immediately if the process returns non-zero.
    """
    cmd = [sys.executable, "-m", "backend.cli", "--isa", isa, "--hex", hex_bytes, "--emit-tcg"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0, f"CLI failed: {proc.stderr or proc.stdout}"
    return proc.stdout


def test_tcg_emit_x86_cmp_je_and_movs():
    hexcode = "48 83 F8 05 74 07 48 C7 C3 01 00 00 00 48 C7 C3 02 00 00 00"
    out = _run_cli_emit_tcg("x86", hexcode)

    assert "ISA: x86" in out
    assert "tcg_gen_subi_i64" in out and "rax" in out and "5" in out
    assert "tcg_gen_brcondi_i32" in out and "ZF" in out
    assert "tcg_gen_goto_tb" in out
    assert "tcg_gen_movi_i64(rbx, 2)" in out


def test_tcg_emit_arm_mov_cmp_cbz_mov():
    hexcode = "00 00 80 D2 1F 00 00 F1 02 00 00 B4 41 00 80 D2"
    out = _run_cli_emit_tcg("arm", hexcode)

    assert "ISA: arm" in out
    assert "tcg_gen_movi_i64" in out
    assert "tcg_gen_brcondi_i64" in out
    assert "tcg_gen_movi_i64(x1, 2)" in out