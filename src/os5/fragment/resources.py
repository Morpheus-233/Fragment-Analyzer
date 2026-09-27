"""Read-only resource analyzer (OS5 snapshot resources only; never host devices)."""
from __future__ import annotations

from typing import Any, Dict, List


def _get(o: Any, k: str, d: Any = None) -> Any:
    return o.get(k, d) if isinstance(o, dict) else getattr(o, k, d)


def analyze_resources(snapshot: Any) -> Dict[str, Any]:
    res = snapshot.get("resources", []) if isinstance(snapshot, dict) else list(getattr(snapshot, "resources", ()) or ())
    if not isinstance(res, list):
        res = []
    procs = snapshot.get("processes", []) if isinstance(snapshot, dict) else list(getattr(snapshot, "processes", ()) or ())
    pids = {str(_get(p, "pid", _get(p, "id", ""))) for p in procs}
    diags: List[Dict[str, Any]] = []
    by_type: Dict[str, int] = {}
    seen = set()
    for r in res:
        rid = str(_get(r, "res_id", _get(r, "id", "?")))
        rtype = str(_get(r, "res_type", "generic"))
        by_type[rtype] = by_type.get(rtype, 0) + 1
        if rid in seen:
            diags.append({"code": "FRAG009", "severity": "error",
                          "message": f"duplicate resource id {rid}", "fragment": rid,
                          "evidence": {"res_id": rid}})
        seen.add(rid)
        owner = _get(r, "owner_id", None)
        if owner is not None and pids and str(owner) not in pids:
            diags.append({"code": "FRAG008", "severity": "warning",
                          "message": f"resource {rid} owned by unknown process {owner}",
                          "fragment": rid, "evidence": {"res_id": rid, "owner_id": str(owner)}})
    return {"resource_count": len(res), "by_type": by_type, "diagnostics": diags}
