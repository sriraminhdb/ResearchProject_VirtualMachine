import pytest
from backend.executors.qemu_user import run_x86_under_qemu, run_arm64_under_qemu

def _skip_if_missing():
    try:
        from shutil import which
        return which("qemu-x86_64") is None or which("qemu-aarch64") is None
    except Exception:
        return True

pytestmark = pytest.mark.skipif(_skip_if_missing(), reason="qemu-user or helpers not present")

def test_qemu_x86_multi_regs():
    code = bytes.fromhex("48 C7 C3 2A 00 00 00 48 C7 C2 09 00 00 00 C3")
    regs = run_x86_under_qemu(code, {"rbx": 0, "rdx": 0})
    assert regs.get("rbx") == 42
    assert regs.get("rdx") == 9

def test_qemu_arm_multi_regs():
    code = bytes.fromhex("41 05 80 D2 22 01 80 D2 C0 03 5F D6")
    regs = run_arm64_under_qemu(code, {"x1": 0, "x2": 0})
    assert regs.get("x1") == 42
    assert regs.get("x2") == 9
