"""Read-only kernel-object analyzer (observer only)."""
from __future__ import annotations

from typing import Any, Dict, List


def _get(o: Any, k: str, d: Any = None) -> Any:
    return o.get(k, d) if isinstance(o, dict) else getattr(o, k, d)


def analyze_objects(snapshot: Any) -> Dict[str, Any]:
    objs = snapshot.get("kernel_objects", []) if isinstance(snapshot, dict) else list(getattr(snapshot, "kernel_objects", ()) or ())
    if not isinstance(objs, list):
        objs = []
    procs = snapshot.get("processes", []) if isinstance(snapshot, dict) else list(getattr(snapshot, "processes", ()) or ())
    pids = {str(_get(p, "pid", _get(p, "id", ""))) for p in procs}
    diags: List[Dict[str, Any]] = []
    by_type: Dict[str, int] = {}
    seen = set()
    for o in objs:
        oid = str(_get(o, "obj_id", _get(o, "id", "?")))
        otype = str(_get(o, "obj_type", "generic"))
        by_type[otype] = by_type.get(otype, 0) + 1
        if oid in seen:
            diags.append({"code": "FRAG009", "severity": "error",
                          "message": f"duplicate object id {oid}", "fragment": oid,
                          "evidence": {"obj_id": oid}})
        seen.add(oid)
        owner = _get(o, "owner_id", None)
        if owner is not None and pids and str(owner) not in pids:
            diags.append({"code": "FRAG002", "severity": "warning",
                          "message": f"object {oid} owned by unknown process {owner}",
                          "fragment": oid,
                          "evidence": {"obj_id": oid, "owner_id": str(owner)}})
        try:
            raw_rc = _get(o, "refcount", 0)
            rc = int(raw_rc) if raw_rc is not None else 0
        except Exception:
            diags.append({"code": "FRAG005", "severity": "error",
                          "message": f"object {oid} has non-numeric refcount",
                          "fragment": oid, "evidence": {"obj_id": oid}})
            continue
        if rc < 0:
            diags.append({"code": "FRAG005", "severity": "error",
                          "message": f"object {oid} has negative refcount {rc}",
                          "fragment": oid, "evidence": {"obj_id": oid, "refcount": rc}})
        refs = _get(o, "references", []) or []
        if isinstance(refs, (list, tuple)) and len(list(refs)) > 0 and rc != len(list(refs)):
            diags.append({"code": "FRAG005", "severity": "warning",
                          "message": f"object {oid} refcount {rc} != actual references {len(list(refs))}",
                          "fragment": oid,
                          "evidence": {"obj_id": oid, "refcount": rc,
                                       "actual": len(list(refs))}})
    return {"object_count": len(objs), "by_type": by_type, "diagnostics": diags}
