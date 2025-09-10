from __future__ import annotations
import os, shutil, subprocess
from typing import Dict, Optional

QEMU_X86 = "qemu-x86_64"
QEMU_A64 = "qemu-aarch64"
HELPERS_DIR = "third_party/qemu_helpers/bin"

class QemuNotAvailable(RuntimeError): ...
class HelperNotFound(RuntimeError): ...

def _which_or_raise(bin_name: str) -> str:
    path = shutil.which(bin_name)
    if not path:
        raise QemuNotAvailable(f"{bin_name} not found on PATH")
    return path

def _parse_kv_dump(text: str) -> Dict[str, int]:
    out: Dict[str,int] = {}
    for ln in text.splitlines():
        ln = ln.strip()
        if "=" not in ln:
            continue
        k, v = ln.split("=", 1)
        try:
            out[k.strip().lower()] = int(v.strip(), 0)
        except ValueError:
            pass
    return out

def _maybe_set_aarch64_ld_prefix(env: dict) -> None:
    if "QEMU_LD_PREFIX" in env:
        return
    # Common Ubuntu cross root that contains lib/ld-linux-aarch64.so.1
    candidates = (
        "/usr/aarch64-linux-gnu",
        "/usr/arm64-linux-gnu",  # just in case on some distros
    )
    for root in candidates:
        if os.path.exists(os.path.join(root, "lib", "ld-linux-aarch64.so.1")):
            env["QEMU_LD_PREFIX"] = root
            break

def run_x86_under_qemu(code: bytes, init: Optional[Dict[str,int]] = None) -> Dict[str,int]:
    qemu = _which_or_raise(QEMU_X86)
    helper = os.path.join(HELPERS_DIR, "x86_64", "runner")
    if not os.path.exists(helper):
        raise HelperNotFound(helper)

    env = os.environ.copy()
    for k, v in (init or {}).items():
        env[f"INIT_{k.upper()}"] = str(int(v))

    proc = subprocess.run([qemu, helper], input=code, env=env,
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return _parse_kv_dump(proc.stdout.decode("utf-8", "ignore"))

def run_arm64_under_qemu(code: bytes, init: Optional[Dict[str,int]] = None) -> Dict[str,int]:
    qemu = _which_or_raise(QEMU_A64)
    helper = os.path.join(HELPERS_DIR, "aarch64", "runner")
    if not os.path.exists(helper):
        raise HelperNotFound(helper)

    env = os.environ.copy()
    for k, v in (init or {}).items():
        env[f"INIT_{k.upper()}"] = str(int(v))
    _maybe_set_aarch64_ld_prefix(env)

    proc = subprocess.run([qemu, helper], input=code, env=env,
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return _parse_kv_dump(proc.stdout.decode("utf-8", "ignore"))
