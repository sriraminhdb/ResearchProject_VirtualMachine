# backend/orchestrator.py (Debug Fixed Version)

import time
from typing import Optional, List, Dict, Any
from backend.isadetect import detect_isa
from backend.dispatcher import dispatch

class VMState:
    def __init__(self, memory: bytes, registers=None, pc: int = 0):
        # Use mutable memory buffer
        self.memory = bytearray(memory)
        self.registers = registers or {}
        self.pc = pc
        # Flags for conditional logic
        self.flags = {'ZF': False}
        
        # NEW: Track architecture switches
        self.current_isa: Optional[str] = None
        self.switch_count: int = 0
        self.switch_overhead: List[float] = []  # Track timing per switch
        self.switch_log: List[Dict[str, Any]] = []  # Detailed switch history
        self.isa_instruction_counts: Dict[str, int] = {}  # Instructions per ISA
        
    def log_switch(self, from_isa: str, to_isa: str, pc: int, overhead: float):
        """Log an architecture switch with timing information."""
        self.switch_count += 1
        self.switch_overhead.append(overhead)
        self.switch_log.append({
            'switch_id': self.switch_count,
            'from_isa': from_isa,
            'to_isa': to_isa, 
            'pc': pc,
            'overhead_ms': overhead * 1000,
            'timestamp': time.time()
        })
        
    def increment_instruction_count(self, isa: str):
        """Track number of instructions executed per ISA."""
        self.isa_instruction_counts[isa] = self.isa_instruction_counts.get(isa, 0) + 1
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive execution statistics."""
        total_instructions = sum(self.isa_instruction_counts.values())
        avg_switch_overhead = (
            sum(self.switch_overhead) / len(self.switch_overhead)
            if self.switch_overhead else 0.0
        )
        
        return {
            'total_instructions': total_instructions,
            'isa_breakdown': self.isa_instruction_counts.copy(),
            'switch_count': self.switch_count,
            'avg_switch_overhead_ms': avg_switch_overhead * 1000,
            'total_switch_overhead_ms': sum(self.switch_overhead) * 1000,
            'switch_rate': self.switch_count / total_instructions if total_instructions > 0 else 0,
            'final_pc': self.pc,
            'memory_size': len(self.memory)
        }

def map_registers_x86_to_arm(x86_regs: dict) -> dict:
    """Map x86 registers to ARM equivalents during switch."""
    mapping = {
        'rax': 'x0', 'rbx': 'x1', 'rcx': 'x2', 'rdx': 'x3',
        'rsi': 'x4', 'rdi': 'x5', 'rbp': 'x6', 'rsp': 'x7',
        'r8': 'x8',  'r9': 'x9',  'r10': 'x10', 'r11': 'x11',
        'r12': 'x12', 'r13': 'x13', 'r14': 'x14', 'r15': 'x15'
    }
    return {mapping.get(k, k): v for k, v in x86_regs.items() if k in mapping}

def map_registers_arm_to_x86(arm_regs: dict) -> dict:
    """Map ARM registers to x86 equivalents during switch.""" 
    mapping = {
        'x0': 'rax', 'x1': 'rbx', 'x2': 'rcx', 'x3': 'rdx',
        'x4': 'rsi', 'x5': 'rdi', 'x6': 'rbp', 'x7': 'rsp',
        'x8': 'r8',  'x9': 'r9',  'x10': 'r10', 'x11': 'r11',
        'x12': 'r12', 'x13': 'r13', 'x14': 'r14', 'x15': 'r15'
    }
    return {mapping.get(k, k): v for k, v in arm_regs.items() if k in mapping}

def perform_register_mapping(state: VMState, from_isa: str, to_isa: str):
    """Perform cross-architecture register mapping during ISA switch."""
    if from_isa == 'x86' and to_isa == 'arm':
        state.registers = map_registers_x86_to_arm(state.registers)
    elif from_isa == 'arm' and to_isa == 'x86':
        state.registers = map_registers_arm_to_x86(state.registers)
    # Note: flags mapping could be added here too

def run_bytes_adaptive(memory: bytes, enable_register_mapping: bool = True, debug: bool = False) -> VMState:
    """
    Execute with runtime ISA detection and switching.
    
    Args:
        memory: Byte sequence containing potentially mixed ISA instructions
        enable_register_mapping: Whether to map registers across ISA switches
        debug: Enable debug output
        
    Returns:
        VMState with execution results and switch statistics
    """
    # Import here to avoid circular imports
    from backend.runtime_detector import detect_isa_transition, get_instruction_boundaries
    
    state = VMState(memory=memory)
    max_iterations = min(len(memory) * 3, 1000)  # Stricter safety limit
    iteration_count = 0
    
    if debug:
        print(f"Starting adaptive execution of {len(memory)} bytes (max iterations: {max_iterations})")
    
    while state.pc < len(state.memory) and iteration_count < max_iterations:
        iteration_count += 1
        
        if debug and iteration_count % 10 == 0:
            print(f"Debug: Iteration {iteration_count}, PC={state.pc}, ISA={state.current_isa}")
        
        # Safety check: if PC hasn't advanced in a while, force advancement
        old_pc_check = state.pc
        
        # Detect ISA at current PC
        switch_start_time = time.perf_counter()
        
        try:
            current_isa, is_transition = detect_isa_transition(
                state.memory, state.pc, state.current_isa
            )
        except Exception as e:
            if debug:
                print(f"Debug: ISA detection error at PC={state.pc}: {e}")
            current_isa = 'unknown'
            is_transition = False
        
        if current_isa == 'unknown':
            if debug:
                print(f"Debug: Unknown ISA at PC={state.pc}, advancing by 1 byte")
            state.pc += 1
            continue
            
        # Handle ISA transition
        if is_transition:
            switch_end_time = time.perf_counter()
            overhead = switch_end_time - switch_start_time
            
            if debug:
                print(f"Debug: ISA switch at PC={state.pc}: {state.current_isa} -> {current_isa}")
            
            # Perform register mapping if enabled
            if enable_register_mapping:
                perform_register_mapping(state, state.current_isa, current_isa)
                
            # Log the switch
            state.log_switch(state.current_isa, current_isa, state.pc, overhead)
            state.current_isa = current_isa
        
        # Update current ISA if this is the first instruction
        if state.current_isa is None:
            state.current_isa = current_isa
            if debug:
                print(f"Debug: Initial ISA detected: {current_isa}")
        
        # Execute one instruction
        old_pc = state.pc
        try:
            state = dispatch(state.memory, state, current_isa)
            state.increment_instruction_count(current_isa)
            
            # Critical safety check: ensure PC advanced
            if state.pc == old_pc:
                # Force advance to prevent infinite loop
                instr_size = get_instruction_boundaries(state.memory, state.pc, current_isa)
                state.pc += max(instr_size, 1)  # Ensure at least 1 byte advance
                if debug:
                    print(f"Debug: Forced PC advance by {max(instr_size, 1)} bytes at PC={old_pc}")
                    
        except Exception as e:
            if debug:
                print(f"Debug: Execution error at PC={state.pc}, ISA={current_isa}: {e}")
            # On error, advance PC to prevent getting stuck
            state.pc += 1
            continue
    
    # Check if we hit the iteration limit
    if iteration_count >= max_iterations:
        if debug:
            print(f"Debug: Hit maximum iteration limit ({max_iterations})")
    
    # Print final statistics
    if debug:
        stats = state.get_statistics()
        print(f"Debug: Execution completed after {iteration_count} iterations:")
        print(f"  Total instructions: {stats['total_instructions']}")
        print(f"  ISA breakdown: {stats['isa_breakdown']}")
        print(f"  Architecture switches: {stats['switch_count']}")
        if stats['avg_switch_overhead_ms'] > 0:
            print(f"  Average switch overhead: {stats['avg_switch_overhead_ms']:.3f}ms")
    
    return state

def run_bytes(memory: bytes, isa: str) -> VMState:
    """
    Execute instructions in `memory` for the given ISA (original static version).
    """
    state = VMState(memory=memory)
    state.current_isa = isa
    
    max_iterations = min(len(memory) * 2, 500)  # Safety limit
    iteration_count = 0
    
    while state.pc < len(state.memory) and iteration_count < max_iterations:
        iteration_count += 1
        old_pc = state.pc
        
        try:
            state = dispatch(state.memory, state, isa)
            state.increment_instruction_count(isa)
            
            # Safety check
            if state.pc == old_pc:
                state.pc += 1  # Force advance
        except Exception:
            state.pc += 1  # Skip problematic instruction
            
    return state

def run(binary_path: str) -> VMState:
    """
    Detect ISA for the given ELF file at `binary_path`,
    load its bytes, and execute to completion (original static version).
    """
    isa = detect_isa(binary_path)
    with open(binary_path, 'rb') as f:
        mem = f.read()
    return run_bytes(mem, isa)

def run_adaptive(binary_path: str) -> VMState:
    """
    Load binary and execute with adaptive ISA detection.
    """
    with open(binary_path, 'rb') as f:
        mem = f.read()
    return run_bytes_adaptive(mem)

# Keep the old dispatch function for backward compatibility
def dispatch(instr_bytes: bytes, state, isa: str):
    """Dispatch instruction bytes to the appropriate ISA backend."""
    if isa == "x86":
        from backend.backends.x86 import step as x86_step
        return x86_step(instr_bytes, state)
    elif isa == "arm":
        from backend.backends.arm import step as arm_step
        return arm_step(instr_bytes, state)
    else:
        raise ValueError(f"Unsupported ISA: {isa}")