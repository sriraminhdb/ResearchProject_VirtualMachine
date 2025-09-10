import time
import statistics
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from collections import defaultdict

@dataclass 
class SwitchEvent:
    """Record of a single architecture switch event."""
    switch_id: int
    from_isa: str
    to_isa: str
    pc: int
    overhead_seconds: float
    instruction_count_before: int
    timestamp: float
    registers_before: Dict[str, Any]
    registers_after: Dict[str, Any]
    memory_changes: int = 0

class PerformanceProfiler:
    """Detailed performance profiling for adaptive VM execution."""
    
    def __init__(self):
        self.switches: List[SwitchEvent] = []
        self.isa_timings: Dict[str, List[float]] = defaultdict(list)
        self.instruction_timings: List[float] = []
        self.memory_usage: List[int] = []
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        
    def start_profiling(self):
        """Start performance profiling session."""
        self.start_time = time.perf_counter()
        
    def end_profiling(self):
        """End performance profiling session."""
        self.end_time = time.perf_counter()
        
    def record_switch(self, event: SwitchEvent):
        """Record an architecture switch event."""
        self.switches.append(event)
        
    def record_instruction_timing(self, isa: str, execution_time: float):
        """Record timing for a single instruction execution."""
        self.isa_timings[isa].append(execution_time)
        self.instruction_timings.append(execution_time)
        
    def record_memory_usage(self, size: int):
        """Record current memory usage."""
        self.memory_usage.append(size)
        
    def get_switch_statistics(self) -> Dict[str, Any]:
        """Get comprehensive switch statistics."""
        if not self.switches:
            return {
                'total_switches': 0,
                'switch_types': {},
                'avg_switch_overhead_ms': 0.0,
                'max_switch_overhead_ms': 0.0,
                'min_switch_overhead_ms': 0.0,
            }
        
        switch_overheads = [s.overhead_seconds * 1000 for s in self.switches]
        switch_types = defaultdict(int)
        
        for switch in self.switches:
            transition = f"{switch.from_isa}->{switch.to_isa}"
            switch_types[transition] += 1
            
        return {
            'total_switches': len(self.switches),
            'switch_types': dict(switch_types),
            'avg_switch_overhead_ms': statistics.mean(switch_overheads),
            'max_switch_overhead_ms': max(switch_overheads),
            'min_switch_overhead_ms': min(switch_overheads),
            'median_switch_overhead_ms': statistics.median(switch_overheads),
            'std_switch_overhead_ms': statistics.stdev(switch_overheads) if len(switch_overheads) > 1 else 0.0,
        }
        
    def get_instruction_statistics(self) -> Dict[str, Any]:
        """Get instruction execution statistics."""
        if not self.instruction_timings:
            return {'total_instructions': 0}
            
        total_instructions = len(self.instruction_timings)
        avg_timing = statistics.mean(self.instruction_timings) * 1000  # Convert to ms
        
        isa_stats = {}
        for isa, timings in self.isa_timings.items():
            if timings:
                isa_stats[isa] = {
                    'count': len(timings),
                    'avg_time_ms': statistics.mean(timings) * 1000,
                    'total_time_ms': sum(timings) * 1000,
                    'percentage': len(timings) / total_instructions * 100
                }
                
        return {
            'total_instructions': total_instructions,
            'avg_instruction_time_ms': avg_timing,
            'isa_breakdown': isa_stats,
            'instructions_per_second': total_instructions / (self.get_total_time() or 1)
        }
        
    def get_memory_statistics(self) -> Dict[str, Any]:
        """Get memory usage statistics."""
        if not self.memory_usage:
            return {'peak_memory': 0, 'avg_memory': 0}
            
        return {
            'peak_memory': max(self.memory_usage),
            'avg_memory': statistics.mean(self.memory_usage),
            'min_memory': min(self.memory_usage),
            'memory_growth': self.memory_usage[-1] - self.memory_usage[0] if len(self.memory_usage) > 1 else 0
        }
        
    def get_total_time(self) -> float:
        """Get total execution time in seconds."""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0
        
    def get_comprehensive_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        return {
            'execution_summary': {
                'total_time_seconds': self.get_total_time(),
                'total_time_ms': self.get_total_time() * 1000,
            },
            'switch_analysis': self.get_switch_statistics(),
            'instruction_analysis': self.get_instruction_statistics(),
            'memory_analysis': self.get_memory_statistics(),
            'efficiency_metrics': self.get_efficiency_metrics(),
        }
        
    def get_efficiency_metrics(self) -> Dict[str, Any]:
        """Calculate efficiency metrics."""
        switch_stats = self.get_switch_statistics()
        instr_stats = self.get_instruction_statistics()
        
        total_time = self.get_total_time()
        total_switches = switch_stats['total_switches']
        total_instructions = instr_stats['total_instructions']
        
        switch_overhead_ratio = 0.0
        if total_time > 0 and 'avg_switch_overhead_ms' in switch_stats:
            total_switch_overhead = (switch_stats['avg_switch_overhead_ms'] / 1000) * total_switches
            switch_overhead_ratio = total_switch_overhead / total_time
            
        return {
            'switch_overhead_ratio': switch_overhead_ratio,
            'switches_per_instruction': total_switches / total_instructions if total_instructions > 0 else 0,
            'instructions_per_switch': total_instructions / total_switches if total_switches > 0 else float('inf'),
            'switch_frequency_hz': total_switches / total_time if total_time > 0 else 0,
        }

class AdaptiveMetricsCollector:
    """Enhanced metrics collection for VMState."""
    
    def __init__(self):
        self.profiler = PerformanceProfiler()
        self.switch_patterns: List[str] = []
        self.register_mappings: List[Dict[str, Any]] = []
        self.error_log: List[Dict[str, Any]] = []
        
    def start_execution(self):
        """Start metrics collection."""
        self.profiler.start_profiling()
        
    def end_execution(self):
        """End metrics collection."""
        self.profiler.end_profiling()
        
    def record_switch(self, from_isa: str, to_isa: str, pc: int, overhead: float,
                     instr_count: int, regs_before: dict, regs_after: dict):
        """Record an architecture switch with full context."""
        event = SwitchEvent(
            switch_id=len(self.profiler.switches) + 1,
            from_isa=from_isa,
            to_isa=to_isa,
            pc=pc,
            overhead_seconds=overhead,
            instruction_count_before=instr_count,
            timestamp=time.time(),
            registers_before=regs_before.copy(),
            registers_after=regs_after.copy()
        )
        
        self.profiler.record_switch(event)
        self.switch_patterns.append(f"{from_isa}->{to_isa}")
        
        # Record register mapping info
        self.register_mappings.append({
            'switch_id': event.switch_id,
            'mapped_registers': len(set(regs_after.keys()) & set(regs_before.keys())),
            'new_registers': len(set(regs_after.keys()) - set(regs_before.keys())),
            'lost_registers': len(set(regs_before.keys()) - set(regs_after.keys())),
        })
        
    def record_instruction(self, isa: str, execution_time: float):
        """Record instruction execution timing."""
        self.profiler.record_instruction_timing(isa, execution_time)
        
    def record_error(self, error_type: str, message: str, pc: int, isa: str):
        """Record execution error."""
        self.error_log.append({
            'timestamp': time.time(),
            'error_type': error_type,
            'message': message,
            'pc': pc,
            'isa': isa
        })
        
    def get_pattern_analysis(self) -> Dict[str, Any]:
        """Analyze switch patterns."""
        if not self.switch_patterns:
            return {'patterns': {}}
            
        pattern_counts = defaultdict(int)
        for pattern in self.switch_patterns:
            pattern_counts[pattern] += 1
            
        # Find common sequences
        sequences = []
        for i in range(len(self.switch_patterns) - 1):
            seq = f"{self.switch_patterns[i]} -> {self.switch_patterns[i+1]}"
            sequences.append(seq)
            
        sequence_counts = defaultdict(int)
        for seq in sequences:
            sequence_counts[seq] += 1
            
        return {
            'patterns': dict(pattern_counts),
            'pattern_sequences': dict(sequence_counts),
            'unique_patterns': len(pattern_counts),
            'most_common_pattern': max(pattern_counts.items(), key=lambda x: x[1]) if pattern_counts else None,
        }
        
    def get_register_mapping_analysis(self) -> Dict[str, Any]:
        """Analyze register mapping effectiveness."""
        if not self.register_mappings:
            return {'total_mappings': 0}
            
        total_mapped = sum(m['mapped_registers'] for m in self.register_mappings)
        total_new = sum(m['new_registers'] for m in self.register_mappings)
        total_lost = sum(m['lost_registers'] for m in self.register_mappings)
        
        return {
            'total_mappings': len(self.register_mappings),
            'avg_mapped_registers': total_mapped / len(self.register_mappings),
            'avg_new_registers': total_new / len(self.register_mappings),
            'avg_lost_registers': total_lost / len(self.register_mappings),
            'mapping_efficiency': total_mapped / (total_mapped + total_lost) if (total_mapped + total_lost) > 0 else 0.0,
        }
        
    def get_full_report(self) -> Dict[str, Any]:
        """Generate complete metrics report."""
        base_report = self.profiler.get_comprehensive_report()
        
        base_report.update({
            'pattern_analysis': self.get_pattern_analysis(),
            'register_mapping_analysis': self.get_register_mapping_analysis(),
            'error_summary': {
                'total_errors': len(self.error_log),
                'error_types': list(set(e['error_type'] for e in self.error_log)),
                'errors': self.error_log[-10:]  # Last 10 errors
            }
        })
        
        return base_report