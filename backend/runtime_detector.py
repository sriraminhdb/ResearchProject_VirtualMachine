def detect_isa_at_runtime(instr_bytes: bytes, pc: int) -> str:
    """
    Detect ISA based on instruction format at current PC.
    Returns 'x86', 'arm', or 'unknown'
    
    Detection heuristics:
    - ARM64: Fixed 4-byte instructions, specific bit patterns
    - x86-64: Variable length, REX prefixes, common opcodes
    """
    if pc >= len(instr_bytes):
        return 'unknown'
    
    # Need at least 1 byte for basic detection, 4 bytes for reliable detection
    remaining = len(instr_bytes) - pc
    if remaining < 1:
        return 'unknown'
    
    # Get available bytes for analysis
    available_bytes = min(remaining, 4)
    window = instr_bytes[pc:pc+available_bytes]
    
    # ARM64 Detection Heuristics (needs 4 bytes)
    if available_bytes >= 4 and is_likely_arm64(window):
        return 'arm'
    
    # x86-64 Detection Heuristics (can work with 1+ bytes)
    if is_likely_x86_64(window, instr_bytes, pc):
        return 'x86'
    
    # If we have 4 bytes and neither matched strongly, try again with looser criteria
    if available_bytes >= 4:
        if is_arm64_loose(window):
            return 'arm'
    
    # Default fallback based on common patterns
    if available_bytes > 0:
        first_byte = window[0]
        # Very common x86 opcodes
        if first_byte in [0x90, 0xCC, 0xC3]:  # NOP, INT3, RET
            return 'x86'
        # REX prefix is strong x86-64 indicator
        if 0x40 <= first_byte <= 0x4F:
            return 'x86'
    
    return 'unknown'

def is_likely_arm64(instr_bytes: bytes) -> bool:
    """
    Check if 4-byte sequence looks like ARM64 instruction.
    ARM64 has fixed 32-bit instruction length with specific patterns.
    """
    if len(instr_bytes) < 4:
        return False
    
    instr = int.from_bytes(instr_bytes[:4], 'little')
    
    # Common ARM64 instruction patterns
    arm64_patterns = [
        # MOV (wide immediate): 110100101 + bits
        (0x52800000, 0xFFE00000),  # MOVZ W
        (0xD2800000, 0xFFE00000),  # MOVZ X
        
        # ADD (immediate): 0010001 + bits  
        (0x11000000, 0xFF800000),  # ADD W
        (0x91000000, 0xFF800000),  # ADD X
        
        # B (unconditional): 000101 + 26-bit offset
        (0x14000000, 0xFC000000),  # B
        
        # CBZ: 0110100 + bits
        (0x34000000, 0xFE000000),  # CBZ W
        (0xB4000000, 0xFE000000),  # CBZ X
        
        # LDR (literal): 01011000 + bits or 01111000 + bits
        (0x18000000, 0xFF000000),  # LDR W literal
        (0x58000000, 0xFF000000),  # LDR X literal
        
        # NOP: 0xD503201F
        (0xD503201F, 0xFFFFFFFF),
        
        # SUB/SUBS: similar to ADD but different prefix
        (0x51000000, 0xFF800000),  # SUB W
        (0xD1000000, 0xFF800000),  # SUB X
        (0x71000000, 0xFF800000),  # SUBS W  
        (0xF1000000, 0xFF800000),  # SUBS X
        
        # STR/LDR with immediate offset
        (0xF9000000, 0xFF800000),  # STR X, [base, #imm]
        (0xF9400000, 0xFF800000),  # LDR X, [base, #imm]
    ]
    
    for pattern, mask in arm64_patterns:
        if (instr & mask) == pattern:
            return True
    
    return False

def is_arm64_loose(instr_bytes: bytes) -> bool:
    """Looser ARM64 detection for edge cases."""
    if len(instr_bytes) < 4:
        return False
        
    instr = int.from_bytes(instr_bytes[:4], 'little')
    
    # Check for ARM64 instruction format characteristics:
    # - Most instructions have specific bit patterns in upper bits
    # - Condition codes, register fields follow ARM patterns
    
    # Look for register encoding patterns (5-bit register fields)
    # ARM64 often has register fields in bits 0-4, 5-9, 16-20
    
    # This is a more permissive check for instructions we might have missed
    upper_byte = (instr >> 24) & 0xFF
    
    # Common ARM64 upper byte patterns
    arm64_upper_patterns = [
        0xD2, 0xD5, 0x8B, 0xCB, 0xF9, 0xF8, 0xB9, 0xB8,
        0x52, 0x72, 0x92, 0xB2, 0xD2, 0xF2, 0x14, 0x54,
        0x34, 0xB4, 0x36, 0xB6
    ]
    
    return upper_byte in arm64_upper_patterns

def is_likely_x86_64(instr_bytes: bytes, full_bytes: bytes, pc: int) -> bool:
    """
    Check if byte sequence looks like x86-64 instructions.
    x86 has variable length with specific prefixes and opcodes.
    """
    if len(instr_bytes) == 0:
        return False
    
    first_byte = instr_bytes[0]
    
    # Strong x86-64 indicators
    x86_strong_indicators = [
        # REX prefixes (0x40-0x4F) - definitive x86-64 indicator
        lambda b: 0x40 <= b <= 0x4F,
        
        # Common single-byte opcodes
        lambda b: b == 0x90,  # NOP
        lambda b: b == 0xCC,  # INT3
        lambda b: b == 0xC3,  # RET
        lambda b: b == 0xC2,  # RET imm16
        
        # MOV immediate to register (0xB0-0xBF)
        lambda b: 0xB0 <= b <= 0xBF,
        
        # PUSH/POP register (0x50-0x5F)
        lambda b: 0x50 <= b <= 0x5F,
        
        # JMP variants
        lambda b: b == 0xE9,  # JMP rel32
        lambda b: b == 0xEB,  # JMP rel8
        
        # Conditional jumps (0x70-0x7F)
        lambda b: 0x70 <= b <= 0x7F,
        
        # Common ALU operations
        lambda b: b in [0x01, 0x03, 0x05, 0x29, 0x2B, 0x31, 0x33],
    ]
    
    # Check strong indicators first
    for indicator in x86_strong_indicators:
        if indicator(first_byte):
            return True
    
    # Check for two-byte opcodes (0x0F prefix)
    if len(instr_bytes) >= 2 and first_byte == 0x0F:
        second_byte = instr_bytes[1]
        # Many 0x0F prefixed instructions are x86
        return True
    
    # Check for common x86 multi-byte patterns
    if len(instr_bytes) >= 2:
        # MOV r/m, imm patterns
        if first_byte in [0xC6, 0xC7]:  # MOV r/m8, imm8 / MOV r/m32, imm32
            return True
        # MOV reg, r/m patterns
        if first_byte in [0x88, 0x89, 0x8A, 0x8B]:
            return True
        # ADD patterns
        if first_byte in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]:
            return True
        # SUB patterns  
        if first_byte in [0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D]:
            return True
        # CMP patterns
        if first_byte in [0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D]:
            return True
    
    # Check for x86-64 specific patterns (REX + opcode)
    if len(instr_bytes) >= 2 and 0x40 <= first_byte <= 0x4F:
        # This is definitely x86-64
        return True
    
    return False

def get_instruction_boundaries(instr_bytes: bytes, pc: int, isa: str) -> int:
    """
    Get the size of the instruction at PC for the given ISA.
    Used to advance PC correctly after ISA detection.
    """
    if isa == 'arm':
        return 4  # ARM64 instructions are always 4 bytes
    elif isa == 'x86':
        # For x86, we need to actually decode to get length
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_64
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            code = instr_bytes[pc:]
            for insn in md.disasm(code, pc, count=1):
                return insn.size
        except:
            pass
        # Fallback: common instruction sizes
        if pc < len(instr_bytes):
            first_byte = instr_bytes[pc]
            # REX prefix means at least 2 bytes
            if 0x40 <= first_byte <= 0x4F:
                return 2
            # Single byte instructions
            if first_byte in [0x90, 0xC3, 0xCC]:
                return 1
        # Default fallback
        return 1
    else:
        return 1  # Default fallback

def detect_isa_transition(instr_bytes: bytes, pc: int, prev_isa: str) -> tuple:
    """
    Detect ISA and whether a transition occurred.
    Returns (new_isa, transition_occurred)
    """
    new_isa = detect_isa_at_runtime(instr_bytes, pc)
    transition = (prev_isa is not None and 
                 new_isa != 'unknown' and 
                 prev_isa != new_isa)
    return new_isa, transition