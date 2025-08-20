from __future__ import annotations
import json, os, shutil, subprocess, tempfile
from typing import Dict, Optional

QEMU_X86 = os.environ.get("QEMU_X86", "qemu-x86_64")
QEMU_A64 = os.environ.get("QEMU_A64", "qemu-aarch64")

HELPERS_DIR = os.environ.get("QEMU_HELPERS_DIR", "third_party/qemu_helpers/bin")

class QemuNotAvailable(RuntimeError): pass
class HelperNotFound(RuntimeError): pass

def _which_or_raise(bin_name: str) -> str:
    path = shutil.which(bin_name)
    if not path:
        raise QemuNotAvailable(f"{bin_name} not found on PATH")
    return path

def run_x86_under_qemu(code: bytes, init: Optional[Dict[str,int]] = None) -> Dict[str,int]:
    qemu = _which_or_raise(QEMU_X86)
    helper = os.path.join(HELPERS_DIR, "x86_64", "runner")
    if not os.path.exists(helper):
        raise HelperNotFound(helper)

    env = os.environ.copy()
    if init and "rbx" in init:
        env["INIT_RBX"] = str(init["rbx"])

    proc = subprocess.run([qemu, helper], input=code, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    out = proc.stdout.decode("utf-8").strip()
    return json.loads(out)

def run_arm64_under_qemu(code: bytes, init: Optional[Dict[str,int]] = None) -> Dict[str,int]:
    qemu = _which_or_raise(QEMU_A64)
    helper = os.path.join(HELPERS_DIR, "aarch64", "runner")
    if not os.path.exists(helper):
        raise HelperNotFound(helper)

    env = os.environ.copy()
    if init and "x1" in init:
        env["INIT_X1"] = str(init["x1"])

    proc = subprocess.run([qemu, helper], input=code, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    out = proc.stdout.decode("utf-8").strip()
    return json.loads(out)
