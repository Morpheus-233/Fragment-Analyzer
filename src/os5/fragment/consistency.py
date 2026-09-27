"""Consistency engine: observations -> rules -> diagnostics (no auto-repair)."""
from __future__ import annotations

from typing import Any, Dict, List


def _get(o: Any, k: str, d: Any = None) -> Any:
    return o.get(k, d) if isinstance(o, dict) else getattr(o, k, d)


def _list_of(snapshot: Any, attr: str) -> List[Any]:
    if isinstance(snapshot, dict):
        v = snapshot.get(attr, [])
        return v if isinstance(v, list) else []
    return list(getattr(snapshot, attr, ()) or ())


def check_consistency(snapshot: Any, module_results: Dict[str, Any] | None = None) -> Dict[str, Any]:
    diags: List[Dict[str, Any]] = []
    if isinstance(module_results, dict):
        for mod in ("memory", "processes", "objects", "ipc", "resources"):
            r = module_results.get(mod)
            if isinstance(r, dict):
                for d in r.get("diagnostics", []) or []:
                    if isinstance(d, dict):
                        diags.append(d)
    procs = _list_of(snapshot, "processes")
    pids = {str(_get(p, "pid", _get(p, "id", ""))) for p in procs}
    for r in _list_of(snapshot, "memory_regions"):
        owner = _get(r, "owner_id", None)
        rid = str(_get(r, "id", "?"))
        if owner is not None and pids and str(owner) not in pids:
            if not any(d.get("fragment") == rid and d.get("code") == "FRAG002" for d in diags):
                diags.append({"code": "FRAG002", "severity": "warning",
                              "message": f"memory region {rid} owned by unknown process {owner}",
                              "fragment": rid, "location": rid,
                              "evidence": {"region_id": rid, "owner_id": str(owner)}})
    rids = {str(_get(r, "res_id", _get(r, "id", ""))) for r in _list_of(snapshot, "resources")}
    eids = {str(_get(e, "ep_id", _get(e, "id", ""))) for e in _list_of(snapshot, "ipc_endpoints")}
    for p in procs:
        pid = str(_get(p, "pid", _get(p, "id", "?")))
        for rid in list(_get(p, "resource_ids", []) or []):
            if rids and str(rid) not in rids:
                diags.append({"code": "FRAG008", "severity": "warning",
                              "message": f"process {pid} claims unknown resource {rid}",
                              "fragment": pid, "location": pid,
                              "evidence": {"pid": pid, "resource_id": str(rid)}})
        for eid in list(_get(p, "ipc_endpoint_ids", []) or []):
            if eids and str(eid) not in eids:
                diags.append({"code": "FRAG007", "severity": "warning",
                              "message": f"process {pid} claims unknown ipc endpoint {eid}",
                              "fragment": pid, "location": pid,
                              "evidence": {"pid": pid, "ep_id": str(eid)}})
    diags = sorted(diags, key=lambda d: (d.get("code", ""), d.get("fragment", ""), d.get("message", "")))
    has_error = any(d.get("severity") == "error" for d in diags)
    return {"consistent": not has_error, "diagnostics": diags}
