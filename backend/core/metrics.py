from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List

@dataclass
class Metrics:
    total_ms: float = 0.0
    switches: int = 0
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    jit_compile_ms_total: float = 0.0
    jit_blocks_compiled: int = 0
    jit_cache_hits: int = 0
    jit_cache_misses: int = 0

    def add_timeline_point(self, **row):
        self.timeline.append(row)

    def add_jit_compile(self, dt_ms: float):
        self.jit_compile_ms_total += float(dt_ms)
        self.jit_blocks_compiled += 1

    def inc_jit_hit(self):
        self.jit_cache_hits += 1

    def inc_jit_miss(self):
        self.jit_cache_misses += 1
