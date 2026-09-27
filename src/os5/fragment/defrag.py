"""Read-only defragmentation projection (what-if simulation).

`simulate_defrag` answers "what would this address space look like packed?"
without touching anything: it takes a plain snapshot dict and returns a NEW
snapshot dict. The analyzer core stays read-only; this is a hypothetical
projection for the dashboard, clearly flagged via
`metadata["defrag_projection"] = True`.

Packing model (documented, deterministic):
- Regions with non-numeric ranges, `start >= end`, or `start < 0` are
  carried over unchanged so the analyzer still flags them as invalid.
- Regions whose state is not allocated/free/reserved are carried over
  unchanged in their original position (limitation: they may overlap the
  packed area; the analyzer will report that honestly).
- Valid allocated regions keep their relative order and are packed from
  the lowest observed address; reserved regions follow; all free space
  coalesces into one trailing region (`defrag-free`).
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Tuple


def _num(v: Any) -> Tuple[bool, int]:
    try:
        if isinstance(v, bool):
            return True, int(v)
        return True, int(v)
    except Exception:
        return False, 0


def simulate_defrag(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """Return a defragmented projection of a snapshot dict (input untouched)."""
    proj: Dict[str, Any] = copy.deepcopy(snapshot) if isinstance(snapshot, dict) else {}
    regs = proj.get("memory_regions", [])
    if not isinstance(regs, list):
        proj["memory_regions"] = []
        return proj

    valid_alloc: List[Dict[str, Any]] = []
    valid_res: List[Dict[str, Any]] = []
    valid_free: List[Dict[str, Any]] = []
    carried: List[Any] = []
    for r in regs:
        if not isinstance(r, dict):
            carried.append(r)
            continue
        ok_s, s = _num(r.get("start", 0))
        ok_e, e = _num(r.get("end", 0))
        if not (ok_s and ok_e and 0 <= s < e):
            carried.append(r)
            continue
        st = str(r.get("state", ""))
        if st == "allocated":
            valid_alloc.append(r)
        elif st == "reserved":
            valid_res.append(r)
        elif st == "free":
            valid_free.append(r)
        else:
            carried.append(r)

    if not (valid_alloc or valid_res or valid_free):
        proj["memory_regions"] = valid_alloc + valid_res + valid_free + carried
        proj["snapshot_id"] = f"{proj.get('snapshot_id', 'snapshot-0')}-defrag"
        md = proj.get("metadata")
        proj["metadata"] = dict(md) if isinstance(md, dict) else {}
        proj["metadata"]["defrag_projection"] = True
        return proj

    base = min(
        [_num(r.get("start", 0))[1] for r in valid_alloc + valid_res + valid_free]
    )
    packed: List[Dict[str, Any]] = []
    cursor = base
    for r in valid_alloc + valid_res:
        size = _num(r.get("end", 0))[1] - _num(r.get("start", 0))[1]
        nr = dict(r)
        nr["start"] = cursor
        nr["end"] = cursor + size
        packed.append(nr)
        cursor += size
    free_total = sum(_num(r.get("end", 0))[1] - _num(r.get("start", 0))[1]
                     for r in valid_free)
    if free_total > 0:
        packed.append({"id": "defrag-free", "start": cursor,
                       "end": cursor + free_total, "state": "free",
                       "kind": "private", "perms": ["read"], "owner_id": None})

    proj["memory_regions"] = packed + carried
    proj["snapshot_id"] = f"{proj.get('snapshot_id', 'snapshot-0')}-defrag"
    md = proj.get("metadata")
    proj["metadata"] = dict(md) if isinstance(md, dict) else {}
    proj["metadata"]["defrag_projection"] = True
    return proj
