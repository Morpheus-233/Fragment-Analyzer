"""Read-only process/thread analyzer (observer only)."""
from __future__ import annotations

from typing import Any, Dict, List


def _get(o: Any, k: str, d: Any = None) -> Any:
    return o.get(k, d) if isinstance(o, dict) else getattr(o, k, d)


def _list_of(snapshot: Any, attr: str) -> List[Any]:
    if isinstance(snapshot, dict):
        v = snapshot.get(attr, [])
        return v if isinstance(v, list) else []
    return list(getattr(snapshot, attr, ()) or ())


def analyze_processes(snapshot: Any) -> Dict[str, Any]:
    procs = _list_of(snapshot, "processes")
    threads = _list_of(snapshot, "threads")
    pids = set()
    diags: List[Dict[str, Any]] = []
    by_state: Dict[str, int] = {}
    for p in procs:
        pid = str(_get(p, "pid", _get(p, "id", "?")))
        if pid in pids:
            diags.append({"code": "FRAG009", "severity": "error",
                          "message": f"duplicate pid {pid}", "fragment": pid,
                          "evidence": {"pid": pid}})
        pids.add(pid)
        st = str(_get(p, "state", "unknown"))
        by_state[st] = by_state.get(st, 0) + 1
        parent = _get(p, "parent_pid", None)
        if parent is not None and str(parent) not in [str(_get(q, "pid", _get(q, "id", ""))) for q in procs] and str(parent) != "0":
            diags.append({"code": "FRAG006", "severity": "warning",
                          "message": f"process {pid} references unknown parent {parent}",
                          "fragment": pid,
                          "evidence": {"pid": pid, "parent_pid": str(parent)}})
    tids = set()
    for t in threads:
        tid = str(_get(t, "tid", _get(t, "id", "?")))
        if tid in tids:
            diags.append({"code": "FRAG009", "severity": "error",
                          "message": f"duplicate thread id {tid}", "fragment": tid,
                          "evidence": {"tid": tid}})
        tids.add(tid)
        owner = _get(t, "owner_pid", None)
        if owner is not None and str(owner) not in pids:
            diags.append({"code": "FRAG006", "severity": "error",
                          "message": f"thread {tid} owned by unknown process {owner}",
                          "fragment": tid,
                          "evidence": {"tid": tid, "owner_pid": str(owner)}})
    for p in procs:
        pid = str(_get(p, "pid", _get(p, "id", "?")))
        tids_claimed = _get(p, "thread_ids", []) or []
        for tid in (list(tids_claimed) if isinstance(tids_claimed, (list, tuple)) else []):
            if str(tid) not in tids:
                diags.append({"code": "FRAG006", "severity": "warning",
                              "message": f"process {pid} claims unknown thread {tid}",
                              "fragment": pid,
                              "evidence": {"pid": pid, "thread_id": str(tid)}})
    thread_by_state: Dict[str, int] = {}
    for t in threads:
        tst = str(_get(t, "state", "unknown"))
        thread_by_state[tst] = thread_by_state.get(tst, 0) + 1
    rels = [{"kind": "process->thread", "source": str(_get(t, "owner_pid", "")),
             "target": str(_get(t, "tid", _get(t, "id", "")))} for t in threads]
    return {"process_count": len(procs), "thread_count": len(threads),
            "by_state": by_state, "thread_by_state": thread_by_state,
            "relationships": rels, "diagnostics": diags}
