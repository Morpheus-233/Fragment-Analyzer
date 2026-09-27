"""Read-only IPC analyzer (observer only)."""
from __future__ import annotations

from typing import Any, Dict, List


def _get(o: Any, k: str, d: Any = None) -> Any:
    return o.get(k, d) if isinstance(o, dict) else getattr(o, k, d)


def analyze_ipc(snapshot: Any) -> Dict[str, Any]:
    eps = snapshot.get("ipc_endpoints", []) if isinstance(snapshot, dict) else list(getattr(snapshot, "ipc_endpoints", ()) or ())
    if not isinstance(eps, list):
        eps = []
    procs = snapshot.get("processes", []) if isinstance(snapshot, dict) else list(getattr(snapshot, "processes", ()) or ())
    pids = {str(_get(p, "pid", _get(p, "id", ""))) for p in procs}
    diags: List[Dict[str, Any]] = []
    total_msg = 0
    seen = set()
    for e in eps:
        eid = str(_get(e, "ep_id", _get(e, "id", "?")))
        if eid in seen:
            diags.append({"code": "FRAG009", "severity": "error",
                          "message": f"duplicate endpoint id {eid}", "fragment": eid,
                          "evidence": {"ep_id": eid}})
        seen.add(eid)
        try:
            qd = int(_get(e, "queue_depth", 0)); mc = int(_get(e, "message_count", 0))
            cap = int(_get(e, "capacity", 0))
        except Exception:
            diags.append({"code": "FRAG007", "severity": "error",
                          "message": f"endpoint {eid} has non-numeric queue fields",
                          "fragment": eid, "evidence": {"ep_id": eid}})
            continue
        total_msg += max(0, mc)
        if qd < 0 or mc < 0 or cap < 0:
            diags.append({"code": "FRAG007", "severity": "error",
                          "message": f"endpoint {eid} has negative queue field(s)",
                          "fragment": eid,
                          "evidence": {"ep_id": eid, "queue_depth": qd, "message_count": mc, "capacity": cap}})
        if cap > 0 and mc > cap:
            diags.append({"code": "FRAG007", "severity": "error",
                          "message": f"endpoint {eid} over capacity ({mc} > {cap})",
                          "fragment": eid,
                          "evidence": {"ep_id": eid, "message_count": mc, "capacity": cap}})
        if qd != mc:
            diags.append({"code": "FRAG007", "severity": "warning",
                          "message": f"endpoint {eid} queue_depth {qd} != message_count {mc}",
                          "fragment": eid,
                          "evidence": {"ep_id": eid, "queue_depth": qd, "message_count": mc}})
        owner = _get(e, "owner_id", None)
        if owner is not None and pids and str(owner) not in pids:
            diags.append({"code": "FRAG007", "severity": "warning",
                          "message": f"endpoint {eid} owned by unknown process {owner}",
                          "fragment": eid, "evidence": {"ep_id": eid, "owner_id": str(owner)}})
    ep_details = []
    for e in eps:
        eid = str(_get(e, "ep_id", _get(e, "id", "?")))
        try:
            mc = int(_get(e, "message_count", 0))
            cap = int(_get(e, "capacity", 0))
        except Exception:
            mc, cap = 0, 0
        ep_details.append({
            "ep_id": eid,
            "owner_id": str(_get(e, "owner_id", "") or ""),
            "message_count": mc,
            "capacity": cap,
            "utilization": (mc / cap) if cap > 0 else 0.0,
            "state": str(_get(e, "state", "unknown")),
        })
    cap_sum = 0
    for e in eps:
        try:
            c = int(_get(e, "capacity", 0))
            if c > 0:
                cap_sum += c
        except Exception:
            pass
    util = (total_msg / cap_sum) if cap_sum > 0 else 0.0
    return {"endpoint_count": len(eps), "message_count": total_msg,
            "queue_utilization": util, "endpoints": ep_details, "diagnostics": diags}
