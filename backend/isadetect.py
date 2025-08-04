from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

def detect_isa(path: str) -> str:
    """
    Detect the ISA of the given ELF binary.

    Returns:
      - 'x86' for EM_X86_64
      - 'arm' for EM_AARCH64

    Raises:
      ValueError if the file is not a valid ELF, or the e_machine is unsupported.
    """
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            machine = elf['e_machine']
    except (ELFError, KeyError) as e:
        raise ValueError(f"Not a valid ELF file: {e}") from e

    if machine == 'EM_X86_64':
        return 'x86'
    if machine == 'EM_AARCH64':
        return 'arm'
    raise ValueError(f"Unsupported e_machine: {machine}")