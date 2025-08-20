import os
import pytest
from backend.executors.qemu_user import (
    run_x86_under_qemu, run_arm64_under_qemu, QemuNotAvailable, HelperNotFound
)

def _skip_if_missing():
    try:
        os.environ.setdefault("QEMU_HELPERS_DIR", "third_party/qemu_helpers/bin")
        return False
    except Exception:
        return True

@pytest.mark.skipif(_skip_if_missing(), reason="qemu-user or helpers not present")
def test_qemu_x86_mov_rbx_ret():
    code = bytes.fromhex("48 C7 C3 07 00 00 00 C3")
    regs = run_x86_under_qemu(code, {"rbx": 0})
    assert regs["rbx"] == 7

@pytest.mark.skipif(_skip_if_missing(), reason="qemu-user or helpers not present")
def test_qemu_arm_movz_x1_ret():
    code = bytes.fromhex("41 05 80 D2 C0 03 5F D6")
    regs = run_arm64_under_qemu(code, {"x1": 0})
    assert regs["x1"] == 42
