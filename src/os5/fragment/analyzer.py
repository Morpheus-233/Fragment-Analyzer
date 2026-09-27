"""Central read-only Fragment Analyzer API.

Layered flow: snapshot -> memory/process/object/ipc/resource analyzers
-> consistency engine -> statistics engine -> FragmentAnalysis dict.
Gracefully degrades when sibling modules are unavailable.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

try:
    from os5.fragment.snapshot import snapshot_from_dict
except Exception:  # pragma: no cover
    def snapshot_from_dict(d: Any) -> Any:
        return d


def _try_import(name: str, func: str):  # type: ignore[no-untyped-def]
    try:
        mod = __import__(f"os5.fragment.{name}", fromlist=[func])
        return getattr(mod, func)
    except Exception:
        return None


_analyze_memory = _try_import("memory", "analyze_memory")
_analyze_processes = _try_import("process", "analyze_processes")
_analyze_objects = _try_import("kobjects", "analyze_objects")
_analyze_ipc = _try_import("ipc", "analyze_ipc")
_analyze_resources = _try_import("resources", "analyze_resources")
_check_consistency = _try_import("consistency", "check_consistency")
_compute_statistics = _try_import("statistics", "compute_statistics")


@dataclass
class AnalyzerConfig:
    include_memory: bool = True
    include_processes: bool = True
    include_objects: bool = True
    include_ipc: bool = True
    include_resources: bool = True
    strict: bool = False


def _as_snapshot(snapshot: Any) -> Any:
    if isinstance(snapshot, dict):
        try:
            return snapshot_from_dict(snapshot)
        except Exception:
            return snapshot
    return snapshot


def _snap_id(snapshot: Any) -> str:
    if isinstance(snapshot, dict):
        return str(snapshot.get("snapshot_id", "snapshot-0"))
    return str(getattr(snapshot, "snapshot_id", "snapshot-0"))


class FragmentAnalyzer:
    def __init__(self, config: AnalyzerConfig | None = None):
        self.config = config or AnalyzerConfig()

    def analyze(self, snapshot: Any) -> Dict[str, Any]:
        snap = _as_snapshot(snapshot)
        mods: Dict[str, Any] = {}
        if self.config.include_memory and _analyze_memory:
            mods["memory"] = _analyze_memory(snap)
        if self.config.include_processes and _analyze_processes:
            mods["processes"] = _analyze_processes(snap)
        if self.config.include_objects and _analyze_objects:
            mods["objects"] = _analyze_objects(snap)
        if self.config.include_ipc and _analyze_ipc:
            mods["ipc"] = _analyze_ipc(snap)
        if self.config.include_resources and _analyze_resources:
            mods["resources"] = _analyze_resources(snap)
        if _check_consistency:
            cons = _check_consistency(snap, mods)
        else:
            cons = {"consistent": True, "diagnostics": []}
        stats = _compute_statistics(snap, mods) if _compute_statistics else {}
        fragments = []
        for key in ("memory", "processes", "objects", "ipc", "resources"):
            if key in mods:
                fragments.append({"type": key, "summary": {
                    k: v for k, v in mods[key].items() if k != "diagnostics"}})
        diag_list = list(cons.get("diagnostics", []))
        error_count = sum(1 for d in diag_list if d.get("severity") == "error")
        warning_count = sum(1 for d in diag_list if d.get("severity") == "warning")
        info_count = sum(1 for d in diag_list if d.get("severity") == "info")
        return {"snapshot_id": _snap_id(snapshot), "fragments": fragments,
                "statistics": stats,
                "diagnostics": diag_list,
                "consistent": bool(cons.get("consistent", True)),
                "metadata": {"modules": sorted(mods.keys()),
                             "error_count": error_count,
                             "warning_count": warning_count,
                             "info_count": info_count}}

    def analyze_memory(self, snapshot: Any) -> Dict[str, Any]:
        return _analyze_memory(_as_snapshot(snapshot)) if _analyze_memory else {}

    def analyze_process(self, snapshot: Any) -> Dict[str, Any]:
        return _analyze_processes(_as_snapshot(snapshot)) if _analyze_processes else {}

    def analyze_object(self, snapshot: Any) -> Dict[str, Any]:
        return _analyze_objects(_as_snapshot(snapshot)) if _analyze_objects else {}

    def analyze_ipc(self, snapshot: Any) -> Dict[str, Any]:
        return _analyze_ipc(_as_snapshot(snapshot)) if _analyze_ipc else {}

    def analyze_resource(self, snapshot: Any) -> Dict[str, Any]:
        return _analyze_resources(_as_snapshot(snapshot)) if _analyze_resources else {}


def analyze(snapshot: Any, config: AnalyzerConfig | None = None) -> Dict[str, Any]:
    return FragmentAnalyzer(config).analyze(snapshot)
