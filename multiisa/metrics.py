# multiisa/metrics.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List


def _rss_via_resource() -> int:
    try:
        import resource, sys
        ru = resource.getrusage(resource.RUSAGE_SELF)
        rss = ru.ru_maxrss
        if sys.platform.startswith("linux"):
            return int(rss) * 1024  # KiB → bytes
        return int(rss)           # macOS already bytes
    except Exception:
        return 0


def _rss_via_proc() -> int:
    try:
        import os
        with open("/proc/self/statm", "r") as f:
            parts = f.read().split()
        pages = int(parts[1])
        return pages * os.sysconf("SC_PAGESIZE")
    except Exception:
        return 0


def get_rss_bytes() -> int:
    return _rss_via_resource() or _rss_via_proc() or 0


@dataclass
class Metrics:
    # Used by tests
    total_ms: float = 0.0
    switches: int = 0
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    # New enrichments
    total_instrs: int = 0
    switch_latencies_ms: List[float] = field(default_factory=list)
    rss_samples: List[int] = field(default_factory=list)

    def record_switch_latency(self, ms: float) -> None:
        try:
            self.switch_latencies_ms.append(float(ms))
        except Exception:
            pass

    def sample_rss(self) -> None:
        self.rss_samples.append(get_rss_bytes())

    def ips(self) -> float:
        if self.total_ms <= 0:
            return 0.0
        return float(self.total_instrs) / (self.total_ms / 1000.0)

    def rss_summary(self) -> Dict[str, int]:
        if not self.rss_samples:
            return {"min": 0, "max": 0, "avg": 0}
        mn = min(self.rss_samples)
        mx = max(self.rss_samples)
        avg = sum(self.rss_samples) // max(1, len(self.rss_samples))
        return {"min": mn, "max": mx, "avg": avg}

    def to_row(self) -> Dict[str, Any]:
        s = self.rss_summary()
        return {
            "total_ms": round(self.total_ms, 3),
            "switches": self.switches,
            "total_instrs": self.total_instrs,
            "ips": round(self.ips(), 2),
            "switch_latency_avg_ms": round(sum(self.switch_latencies_ms) / max(1, len(self.switch_latencies_ms)), 3)
                if self.switch_latencies_ms else 0.0,
            "rss_min": s["min"],
            "rss_max": s["max"],
            "rss_avg": s["avg"],
            "timeline_len": len(self.timeline),
        }
