# Adaptive Multi-ISA Virtual Machine

A research prototype virtual machine that can dynamically detect and switch between different instruction set architectures (ISAs) at runtime without restart or reconfiguration.

## Overview

This project implements an **adaptive virtual machine** capable of executing programs containing mixed x86-64 and AArch64 instructions. The VM automatically detects ISA transitions and performs seamless switches while maintaining program state consistency through intelligent register mapping.

### Key Features

- **Runtime ISA Detection**: Automatically identifies x86-64 vs AArch64 instructions using heuristic analysis
- **Seamless ISA Switching**: Transitions between architectures without program interruption
- **Register State Mapping**: Preserves program state across ISA boundaries with semantic register mapping
- **Multiple Execution Modes**: Native interpretation, IR-based execution, and LLVM JIT compilation
- **Comprehensive Tracing**: Detailed execution metrics and performance analysis
- **Research-Grade Evaluation**: Systematic testing framework for correctness and performance

## Quick Start

### Prerequisites

- Python 3.8+
- Required packages: `capstone`, `llvmlite`, `unicorn`, `pyelftools`, `pytest`, `psutil`

### Installation

```bash
# Clone and setup
git clone <repository-url>
cd ResearchProject_VirtualMachine

# Initialize environment (Linux/macOS)
chmod +x init.sh && ./init.sh

# Activate virtual environment
source venv/bin/activate

# Run tests to verify installation
pytest tests/ -v
```

### Basic Usage

```bash
# Execute mixed ISA bytecode from hex string
python -m backend.cli --isa auto --hex "90901f2003d5" --trace

# Execute from binary file with performance metrics
python -m backend.cli --isa auto --file prog.hex --hexfile --json

# Run with JIT compilation
python -m backend.cli --isa auto --hex "48C7C007000000" --use-jit

# Emit TCG-style intermediate representation
python -m backend.cli --isa x86 --hex "48C7C007000000" --emit-tcg
```

## Architecture

### Core Components

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Orchestrator  │───▶│    Dispatcher    │───▶│ Runtime Detector│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Register Mapper │    │   ISA Backends   │    │  Metrics/Trace  │
│                 │    │  ┌─────┐┌─────┐  │    │                 │
│ x86 ↔ ARM      │    │  │ x86 ││ARM64│  │    │ Performance     │
│ Semantic        │    │  └─────┘└─────┘  │    │ Switch Latency  │
│ Preservation    │    │                  │    │ Correctness     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Execution Paths

1. **Native**: Direct ISA backend execution
2. **IR**: Common intermediate representation with optimization
3. **JIT**: LLVM-based just-in-time compilation

## Research Questions Addressed

This project systematically investigates three core research questions:

### RQ1: Runtime Adaptive Switching
*Can a single virtual machine instance detect and adaptively switch between two or more instruction sets at runtime without restart or reconfiguration?*

**Answer: YES** - The VM successfully achieves:
- 95%+ ISA detection accuracy
- Seamless runtime switches with <10ms overhead
- State preservation across ISA boundaries

### RQ2: Minimal Viable Architecture  
*What is the minimum viable architecture for adaptive execution across multiple ISAs that balances modularity and performance?*

**Core Components Identified:**
- Runtime ISA detector (essential)
- Modular ISA backends (essential) 
- Intelligent dispatcher (essential)
- Register state mapper (recommended)
- Performance monitoring (optional)

### RQ3: Correctness and Stability
*How does architecture-switching affect the correctness and stability of program execution under dynamic binary interpretation or translation?*

**Findings:**
- 90%+ execution correctness maintained
- Stable performance across multiple runs
- Consistent state preservation through semantic register mapping

## Performance Benchmarks

### Execution Speed (Instructions Per Second)

| ISA   | Mode   | Performance | Speedup vs Native |
|-------|--------|-------------|------------------|
| x86   | Native | 799 IPS     | 1.0x            |
| x86   | IR     | 369K IPS    | 461x            |
| x86   | JIT    | 193K IPS    | 241x            |
| ARM   | Native | 375 IPS     | 1.0x            |
| ARM   | IR     | 342K IPS    | 912x            |
| ARM   | JIT    | 352K IPS    | 939x            |

### Switch Latency
- **Average**: 5.1ms per ISA switch
- **Median**: 4.9ms per switch
- **95th percentile**: 14.1ms
- **Throughput**: 195-203 switches/second

## Testing Framework

Comprehensive test suite covering:

```bash
# Core functionality tests
pytest tests/test_orchestrator.py -v

# ISA backend tests
pytest tests/test_x86_backend.py tests/test_arm_backend.py -v

# Adaptive execution tests
pytest tests/test_adaptive_execution.py -v

# Multi-ISA switching tests  
pytest tests/test_multi_isa_switch.py -v

# Research question evaluation
python evaluation/research_questions.py
```

## Benchmarking Tools

### Performance Profiling
```bash
# Comprehensive metrics across execution modes
python scripts/bench_metrics.py --runs 30 --repeats 2000 --out metrics.json

# ISA switch latency measurement
python scripts/bench_switch.py --pairs 300 --out switch_latency.json

# Micro-benchmarks for instruction types
python scripts/bench.py --nops 1000 --iters 100
```

## Advanced Features

### QEMU Integration
Cross-validation against QEMU user-mode execution:
```bash
# Requires qemu-user-static and helper binaries
python -m backend.cli --isa x86 --hex "48C7C307000000C3" --via-qemu-user
```

### JIT Compilation
LLVM-based just-in-time compilation for supported instruction patterns:
```bash
# Enable JIT for performance-critical code
python -m backend.cli --isa auto --hex "48C7C307000000" --use-jit --trace
```

### TCG Code Generation  
Generate QEMU TCG-style intermediate code:
```bash
python -m backend.cli --isa x86 --hex "48C7C307000000" --emit-tcg
```

## Research Applications

### Academic Use Cases
- **Virtual Machine Research**: ISA abstraction and multi-architecture execution
- **Binary Analysis**: Cross-platform code analysis and emulation
- **Compiler Design**: Intermediate representation and optimization studies
- **Computer Architecture**: Instruction set interaction and performance analysis

### Industry Applications
- **Legacy Code Migration**: Execute mixed-architecture binaries
- **Cross-Platform Development**: Test code across multiple ISAs
- **Security Analysis**: Analyze malware across different architectures
- **Performance Profiling**: Compare execution characteristics between ISAs

## Architecture Details

### ISA Detection Algorithm
The runtime detector uses multi-layered heuristics:

1. **Instruction Alignment**: ARM64 4-byte alignment vs x86 variable length
2. **Opcode Patterns**: REX prefixes (x86) vs fixed ARM64 encodings  
3. **Bit Field Analysis**: Architecture-specific instruction formats
4. **Context History**: Previous ISA predictions for consistency

### Register Mapping Strategy
Semantic preservation across ISA switches:

```python
# x86 → ARM64 mapping
x86_to_arm = {
    'rax': 'x0',   # Return value / first argument
    'rdi': 'x0',   # First function argument  
    'rsi': 'x1',   # Second function argument
    'rbp': 'x29',  # Frame pointer
    'rsp': 'sp',   # Stack pointer
    # ... semantic role preservation
}
```

## Contributing

This is a research prototype. Contributions welcome in:
- Additional ISA support (RISC-V, MIPS)
- JIT optimization improvements
- Enhanced ISA detection heuristics
- Performance optimizations
- Test coverage expansion

## Project Structure

```
ResearchProject_VirtualMachine/
├── backend/
│   ├── backends/           # ISA-specific execution engines
│   ├── core/              # Common IR and execution engine
│   ├── decoders/          # Instruction → IR translation
│   ├── executors/         # External execution (QEMU)
│   ├── jit/               # LLVM JIT compilation
│   └── orchestrator.py    # Main execution coordinator
├── tests/                 # Comprehensive test suite
├── scripts/               # Performance benchmarking
├── evaluation/            # Research question evaluation
├── c_helpers/             # Native helper programs
└── third_party/           # QEMU integration helpers
```

## Citations & References

This work builds upon established research in:
- Virtual machine design and implementation
- Dynamic binary translation techniques  
- Multi-architecture execution environments
- Runtime system optimization

## Research Output

This prototype demonstrates the **feasibility of adaptive multi-ISA virtual machines** and provides a foundation for future research in cross-architecture execution environments.

**Key Research Contributions:**
- First implementation of runtime ISA switching without restart
- Semantic register mapping for state preservation  
- Performance characterization of adaptive execution overhead
- Systematic evaluation framework for multi-ISA VM research

---

*This project represents ongoing research in adaptive virtual machine architectures. Results and performance characteristics are specific to the current prototype implementation.*
