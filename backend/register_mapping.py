from typing import Dict, Any, Optional, Set, Tuple, List
import logging

logger = logging.getLogger(__name__)

class RegisterMapper:
    """
    Handles cross-architecture register mapping during ISA switches.
    Provides bidirectional mapping between x86-64 and AArch64 registers.
    """
    
    # Standard register mappings
    X86_TO_ARM_MAP = {
        # General purpose registers (64-bit)
        'rax': 'x0', 'rbx': 'x1', 'rcx': 'x2', 'rdx': 'x3',
        'rsi': 'x4', 'rdi': 'x5', 'rbp': 'x6', 'rsp': 'x7',
        'r8': 'x8',  'r9': 'x9',  'r10': 'x10', 'r11': 'x11',
        'r12': 'x12', 'r13': 'x13', 'r14': 'x14', 'r15': 'x15',
        
        # 32-bit variants
        'eax': 'w0', 'ebx': 'w1', 'ecx': 'w2', 'edx': 'w3',
        'esi': 'w4', 'edi': 'w5', 'ebp': 'w6', 'esp': 'w7',
        'r8d': 'w8', 'r9d': 'w9', 'r10d': 'w10', 'r11d': 'w11',
        'r12d': 'w12', 'r13d': 'w13', 'r14d': 'w14', 'r15d': 'w15',
    }
    
    ARM_TO_X86_MAP = {v: k for k, v in X86_TO_ARM_MAP.items() if k in [
        'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
        'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'
    ]}
    
    # Special purpose registers
    X86_SPECIAL = {
        'rip': 'pc',  # Program counter
        'rflags': 'nzcv',  # Flags register
    }
    
    ARM_SPECIAL = {v: k for k, v in X86_SPECIAL.items()}
    
    def __init__(self, strategy: str = 'best_effort'):
        """
        Initialize register mapper.
        
        Args:
            strategy: Mapping strategy ('best_effort', 'strict', 'preserve_semantics')
        """
        self.strategy = strategy
        self.mapping_history: List[Dict[str, Any]] = []
        
    def map_x86_to_arm(self, x86_registers: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Map x86 registers to ARM equivalents.
        
        Returns:
            (mapped_registers, unmapped_registers)
        """
        mapped = {}
        unmapped = {}
        
        for reg_name, value in x86_registers.items():
            if reg_name in self.X86_TO_ARM_MAP:
                arm_reg = self.X86_TO_ARM_MAP[reg_name]
                mapped[arm_reg] = value
            elif reg_name in self.X86_SPECIAL:
                # Handle special registers
                arm_reg = self.X86_SPECIAL[reg_name]
                if reg_name == 'rflags':
                    mapped[arm_reg] = self._map_x86_flags_to_arm(value)
                else:
                    mapped[arm_reg] = value
            else:
                unmapped[reg_name] = value
                
        self._log_mapping('x86->arm', x86_registers, mapped, unmapped)
        return mapped, unmapped
        
    def map_arm_to_x86(self, arm_registers: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Map ARM registers to x86 equivalents.
        
        Returns:
            (mapped_registers, unmapped_registers)
        """
        mapped = {}
        unmapped = {}
        
        for reg_name, value in arm_registers.items():
            if reg_name in self.ARM_TO_X86_MAP:
                x86_reg = self.ARM_TO_X86_MAP[reg_name]
                mapped[x86_reg] = value
            elif reg_name in self.ARM_SPECIAL:
                # Handle special registers
                x86_reg = self.ARM_SPECIAL[reg_name]
                if reg_name == 'nzcv':
                    mapped[x86_reg] = self._map_arm_flags_to_x86(value)
                else:
                    mapped[x86_reg] = value
            else:
                unmapped[reg_name] = value
                
        self._log_mapping('arm->x86', arm_registers, mapped, unmapped)
        return mapped, unmapped
        
    def _map_x86_flags_to_arm(self, rflags: int) -> int:
        """
        Map x86 RFLAGS to ARM NZCV flags.
        
        x86 RFLAGS bits:
        - ZF (bit 6): Zero flag
        - CF (bit 0): Carry flag
        - SF (bit 7): Sign flag
        - OF (bit 11): Overflow flag
        
        ARM NZCV bits (in PSTATE):
        - N (bit 31): Negative
        - Z (bit 30): Zero
        - C (bit 29): Carry
        - V (bit 28): Overflow
        """
        arm_flags = 0
        
        # Zero flag: x86 ZF -> ARM Z
        if rflags & (1 << 6):  # ZF
            arm_flags |= (1 << 30)
            
        # Carry flag: x86 CF -> ARM C
        if rflags & (1 << 0):  # CF
            arm_flags |= (1 << 29)
            
        # Sign/Negative flag: x86 SF -> ARM N
        if rflags & (1 << 7):  # SF
            arm_flags |= (1 << 31)
            
        # Overflow flag: x86 OF -> ARM V
        if rflags & (1 << 11):  # OF
            arm_flags |= (1 << 28)
            
        return arm_flags
        
    def _map_arm_flags_to_x86(self, nzcv: int) -> int:
        """Map ARM NZCV flags to x86 RFLAGS."""
        x86_flags = 0x202  # Default RFLAGS value (bit 1 always set, bit 9 IF)
        
        # Zero flag: ARM Z -> x86 ZF
        if nzcv & (1 << 30):  # Z
            x86_flags |= (1 << 6)
            
        # Carry flag: ARM C -> x86 CF
        if nzcv & (1 << 29):  # C
            x86_flags |= (1 << 0)
            
        # Negative flag: ARM N -> x86 SF
        if nzcv & (1 << 31):  # N
            x86_flags |= (1 << 7)
            
        # Overflow flag: ARM V -> x86 OF
        if nzcv & (1 << 28):  # V
            x86_flags |= (1 << 11)
            
        return x86_flags
        
    def _log_mapping(self, direction: str, source: Dict, mapped: Dict, unmapped: Dict):
        """Log mapping operation for debugging."""
        mapping_info = {
            'direction': direction,
            'source_count': len(source),
            'mapped_count': len(mapped),
            'unmapped_count': len(unmapped),
            'mapping_efficiency': len(mapped) / len(source) if source else 0.0,
            'unmapped_registers': list(unmapped.keys())
        }
        
        self.mapping_history.append(mapping_info)
        
        if unmapped and logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Register mapping {direction}: {len(unmapped)} unmapped registers: {list(unmapped.keys())}")
            
    def get_mapping_statistics(self) -> Dict[str, Any]:
        """Get statistics about register mappings performed."""
        if not self.mapping_history:
            return {'total_mappings': 0}
            
        total_mappings = len(self.mapping_history)
        x86_to_arm = [m for m in self.mapping_history if m['direction'] == 'x86->arm']
        arm_to_x86 = [m for m in self.mapping_history if m['direction'] == 'arm->x86']
        
        def avg_efficiency(mappings):
            return sum(m['mapping_efficiency'] for m in mappings) / len(mappings) if mappings else 0.0
            
        return {
            'total_mappings': total_mappings,
            'x86_to_arm_count': len(x86_to_arm),
            'arm_to_x86_count': len(arm_to_x86),
            'x86_to_arm_efficiency': avg_efficiency(x86_to_arm),
            'arm_to_x86_efficiency': avg_efficiency(arm_to_x86),
            'overall_efficiency': avg_efficiency(self.mapping_history),
        }

class SemanticRegisterMapper(RegisterMapper):
    """
    Enhanced register mapper that preserves semantic meaning across architectures.
    """
    
    # Semantic role mappings (based on calling conventions)
    SEMANTIC_ROLES = {
        'x86': {
            'return_value': 'rax',
            'first_arg': 'rdi', 'second_arg': 'rsi', 'third_arg': 'rdx',
            'fourth_arg': 'rcx', 'fifth_arg': 'r8', 'sixth_arg': 'r9',
            'stack_pointer': 'rsp', 'base_pointer': 'rbp',
            'callee_saved': ['rbx', 'rbp', 'r12', 'r13', 'r14', 'r15'],
            'caller_saved': ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'],
        },
        'arm': {
            'return_value': 'x0',
            'first_arg': 'x0', 'second_arg': 'x1', 'third_arg': 'x2',
            'fourth_arg': 'x3', 'fifth_arg': 'x4', 'sixth_arg': 'x5',
            'stack_pointer': 'sp', 'base_pointer': 'x29',  # Frame pointer
            'callee_saved': ['x19', 'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29'],
            'caller_saved': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15'],
        }
    }
    
    def map_with_semantics(self, source_regs: Dict[str, Any], 
                          from_isa: str, to_isa: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """
        Map registers preserving their semantic roles.
        
        Returns:
            (mapped_registers, unmapped_registers)
        """
        if from_isa not in self.SEMANTIC_ROLES or to_isa not in self.SEMANTIC_ROLES:
            # Fall back to basic mapping
            if from_isa == 'x86' and to_isa == 'arm':
                return self.map_x86_to_arm(source_regs)
            else:
                return self.map_arm_to_x86(source_regs)
                
        source_roles = self.SEMANTIC_ROLES[from_isa]
        target_roles = self.SEMANTIC_ROLES[to_isa]
        
        mapped = {}
        unmapped = {}
        
        # Create reverse lookup for source ISA
        source_role_map = {}
        for role, reg in source_roles.items():
            if isinstance(reg, str):
                source_role_map[reg] = role
            elif isinstance(reg, list):
                for r in reg:
                    source_role_map[r] = role
                    
        # Map based on semantic roles
        for reg_name, value in source_regs.items():
            role = source_role_map.get(reg_name)
            if role and role in target_roles:
                target_reg = target_roles[role]
                if isinstance(target_reg, str):
                    mapped[target_reg] = value
                else:
                    # Handle lists (like callee_saved) - use first available
                    mapped[target_reg[0]] = value
            else:
                # Fall back to basic mapping
                if from_isa == 'x86' and to_isa == 'arm':
                    if reg_name in self.X86_TO_ARM_MAP:
                        mapped[self.X86_TO_ARM_MAP[reg_name]] = value
                    else:
                        unmapped[reg_name] = value
                elif from_isa == 'arm' and to_isa == 'x86':
                    if reg_name in self.ARM_TO_X86_MAP:
                        mapped[self.ARM_TO_X86_MAP[reg_name]] = value
                    else:
                        unmapped[reg_name] = value
                else:
                    unmapped[reg_name] = value
                    
        self._log_mapping(f'{from_isa}->{to_isa}', source_regs, mapped, unmapped)
        return mapped, unmapped

def create_register_mapper(strategy: str = 'best_effort') -> RegisterMapper:
    """
    Factory function to create appropriate register mapper.
    
    Args:
        strategy: 'best_effort', 'strict', or 'semantic'
    """
    if strategy == 'semantic':
        return SemanticRegisterMapper(strategy)
    else:
        return RegisterMapper(strategy)

# Convenience functions for direct use
def map_registers_x86_to_arm(x86_regs: Dict[str, Any], strategy: str = 'best_effort') -> Dict[str, Any]:
    """Map x86 registers to ARM equivalents (convenience function)."""
    mapper = create_register_mapper(strategy)
    mapped, _ = mapper.map_x86_to_arm(x86_regs)
    return mapped

def map_registers_arm_to_x86(arm_regs: Dict[str, Any], strategy: str = 'best_effort') -> Dict[str, Any]:
    """Map ARM registers to x86 equivalents (convenience function).""" 
    mapper = create_register_mapper(strategy)
    mapped, _ = mapper.map_arm_to_x86(arm_regs)
    return mapped

def perform_register_mapping(state, from_isa: str, to_isa: str, 
                           strategy: str = 'best_effort') -> Dict[str, Any]:
    """
    Perform cross-architecture register mapping during ISA switch.
    
    Returns:
        Dictionary with mapping statistics
    """
    mapper = create_register_mapper(strategy)
    old_regs = state.registers.copy()
    
    if from_isa == 'x86' and to_isa == 'arm':
        mapped, unmapped = mapper.map_x86_to_arm(state.registers)
    elif from_isa == 'arm' and to_isa == 'x86':
        mapped, unmapped = mapper.map_arm_to_x86(state.registers)
    else:
        mapped, unmapped = state.registers.copy(), {}
        
    state.registers = mapped
    
    return {
        'original_count': len(old_regs),
        'mapped_count': len(mapped),
        'unmapped_count': len(unmapped),
        'unmapped_registers': list(unmapped.keys()),
        'mapping_efficiency': len(mapped) / len(old_regs) if old_regs else 1.0,
        'strategy': strategy
    }