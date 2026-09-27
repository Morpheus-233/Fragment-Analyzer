"""Read-only memory fragment analyzer with fragmentation metrics.

Metrics (all on half-open [start, end) intervals):
- total: sum(end-start) over valid regions (end > start, start >= 0)
- used: sum over state == "allocated"
- free: sum over state == "free"
- free_fragments: count of regions with state == "free" (valid only)
- largest_free / smallest_free / average_free over valid free regions
- external_fragmentation = 1 - largest_free / free when free > 0 else 0.0

Limitations: formula measures contiguity of free space, not allocatability
for a given size class; reserved regions count toward total but neither
used nor free; invalid regions are excluded from sums and reported.
Observer only: never merges/splits/frees.
"""
from __future__ import annotations

from typing import Any, Dict, List


def _regions_of(snapshot: Any) -> List[Any]:
    if isinstance(snapshot, dict):
        regs = snapshot.get("memory_regions", [])
        return regs if isinstance(regs, list) else []
    return list(getattr(snapshot, "memory_regions", ()) or ())


def _get(r: Any, key: str, default: Any = None) -> Any:
    if isinstance(r, dict):
        return r.get(key, default)
    return getattr(r, key, default)


def analyze_memory(snapshot: Any) -> Dict[str, Any]:
    regs = _regions_of(snapshot)
    diags: List[Dict[str, Any]] = []
    valid: List[Any] = []
    seen_ids: Dict[str, int] = {}
    for r in regs:
        rid = str(_get(r, "id", "?"))
        seen_ids[rid] = seen_ids.get(rid, 0) + 1
        try:
            start = int(_get(r, "start", 0))
            end = int(_get(r, "end", 0))
        except Exception:
            diags.append({"code": "FRAG001", "severity": "error",
                          "message": f"invalid numeric range for region {rid}",
                          "fragment": rid, "evidence": {"id": rid}})
            continue
        if not (0 <= start < end):
            diags.append({"code": "FRAG001", "severity": "error",
                          "message": f"invalid fragment range [{start}, {end})",
                          "fragment": rid,
                          "evidence": {"id": rid, "start": start, "end": end}})
            continue
        valid.append(r)
        if seen_ids[rid] > 1:
            diags.append({"code": "FRAG009", "severity": "error",
                          "message": f"duplicate region id {rid}",
                          "fragment": rid, "evidence": {"id": rid}})

    order = sorted(valid, key=lambda r: (int(_get(r, "start", 0)), str(_get(r, "id", ""))))
    for i, a in enumerate(order):
        a0, a1 = int(_get(a, "start", 0)), int(_get(a, "end", 0))
        for b in order[i + 1:]:
            b0, b1 = int(_get(b, "start", 0)), int(_get(b, "end", 0))
            if b0 >= a1:
                break
            if max(a0, b0) < min(a1, b1):
                ov0, ov1 = max(a0, b0), min(a1, b1)
                diags.append({"code": "FRAG003", "severity": "error",
                              "message": "memory regions overlap",
                              "fragment": str(_get(a, "id", "?")),
                              "evidence": {"region_a": {"id": str(_get(a, "id", "?")), "start": a0, "end": a1},
                                           "region_b": {"id": str(_get(b, "id", "?")), "start": b0, "end": b1},
                                           "overlap": [ov0, ov1]}})

    def _size(r: Any) -> int:
        return int(_get(r, "end", 0)) - int(_get(r, "start", 0))

    total = sum(_size(r) for r in valid)
    used = sum(_size(r) for r in valid if str(_get(r, "state", "")) == "allocated")
    free_sizes = [_size(r) for r in valid if str(_get(r, "state", "")) == "free"]
    free = sum(free_sizes)
    n_free = len(free_sizes)
    largest = max(free_sizes) if free_sizes else 0
    smallest = min(free_sizes) if free_sizes else 0
    average = (free / n_free) if n_free else 0
    ext = (1.0 - largest / free) if free > 0 else 0.0

    echo = []
    for r in order:
        if isinstance(r, dict):
            echo.append(dict(r))
        else:
            try:
                echo.append(r.to_dict())
            except Exception:
                echo.append({"id": str(_get(r, "id", "?"))})
    utilization = (used / total) if total > 0 else 0.0
    return {"total": total, "used": used, "free": free,
            "utilization": utilization,
            "free_fragments": n_free, "largest_free": largest,
            "smallest_free": smallest, "average_free": average,
            "external_fragmentation": ext,
            "regions": echo, "diagnostics": diags}
