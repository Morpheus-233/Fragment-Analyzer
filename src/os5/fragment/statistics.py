"""Statistics engine: aggregate read-only counters (deterministic)."""
from __future__ import annotations

from typing import Any, Dict


def compute_statistics(snapshot: Any, module_results: Dict[str, Any] | None = None) -> Dict[str, Any]:
    mods = module_results if isinstance(module_results, dict) else {}
    stats: Dict[str, Any] = {}
    mem = mods.get("memory")
    if isinstance(mem, dict):
        stats["memory"] = {"total": mem.get("total", 0), "used": mem.get("used", 0),
                            "free": mem.get("free", 0),
                            "utilization": mem.get("utilization", 0.0),
                            "fragment_count": mem.get("free_fragments", 0),
                            "largest_fragment": mem.get("largest_free", 0)}
    pr = mods.get("processes")
    if isinstance(pr, dict):
        stats["processes"] = {"process_count": pr.get("process_count", 0),
                               "thread_count": pr.get("thread_count", 0),
                               "by_state": dict(pr.get("by_state", {})),
                               "thread_by_state": dict(pr.get("thread_by_state", {}))}
    ob = mods.get("objects")
    if isinstance(ob, dict):
        stats["objects"] = {"object_count": ob.get("object_count", 0),
                             "by_type": dict(ob.get("by_type", {}))}
    ipc = mods.get("ipc")
    if isinstance(ipc, dict):
        stats["ipc"] = {"endpoint_count": ipc.get("endpoint_count", 0),
                         "message_count": ipc.get("message_count", 0),
                         "queue_utilization": ipc.get("queue_utilization", 0.0)}
    rs = mods.get("resources")
    if isinstance(rs, dict):
        stats["resources"] = {"resource_count": rs.get("resource_count", 0),
                               "by_type": dict(rs.get("by_type", {}))}
    return stats
