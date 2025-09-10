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
