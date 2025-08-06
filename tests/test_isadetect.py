import os
import tempfile
import pytest
from struct import pack
from backend.isadetect import detect_isa
from elftools.common.exceptions import ELFError

def make_minimal_elf(e_machine: int) -> bytes:
    """
    Create a minimal 64-byte ELF header for little-endian 64-bit
    with the given e_machine value.
    """
    header = bytearray(64)
    # ELF magic
    header[0:4] = b'\x7fELF'
    header[4] = 2             # EI_CLASS = ELFCLASS64
    header[5] = 1             # EI_DATA = ELFDATA2LSB
    # e_machine is a 2-byte little-endian at offset 18
    header[18:20] = pack('<H', e_machine)
    return bytes(header)

@pytest.mark.parametrize('machine,expected', [
    (0x3E, 'x86'),   # EM_X86_64 = 62
    (0xB7, 'arm'),   # EM_AARCH64 = 183
])
def test_detect_valid(tmp_path, machine, expected):
    elf_bytes = make_minimal_elf(machine)
    path = tmp_path / f'min_{machine:x}.elf'
    path.write_bytes(elf_bytes)
    assert detect_isa(str(path)) == expected

def test_detect_non_elf(tmp_path):
    # random bytes that don’t start with ELF magic
    bad = tmp_path / 'bad.bin'
    bad.write_bytes(b'\x00\x01\x02\x03\x04')
    with pytest.raises(ValueError) as exc:
        detect_isa(str(bad))
    # Should mention "Not a valid ELF"
    assert "Not a valid ELF file" in str(exc.value)