"""Human + JSON report renderers (no host data leakage)."""
from __future__ import annotations

import json
from typing import Any, Dict


def to_json(analysis: Dict[str, Any]) -> str:
    return json.dumps(analysis, sort_keys=True, indent=2)


def to_text(analysis: Dict[str, Any]) -> str:
    lines = [
        "=" * 60,
        f"  OS5 Fragment Analysis: {analysis.get('snapshot_id', '?')}",
        "=" * 60,
    ]
    consistent = analysis.get("consistent", True)
    meta = analysis.get("metadata", {}) or {}
    ec = meta.get("error_count", 0)
    wc = meta.get("warning_count", 0)
    ic = meta.get("info_count", 0)
    if consistent:
        lines.append("  Status: CONSISTENT [OK]")
    else:
        lines.append(f"  Status: INCONSISTENT [FAIL]  ({ec} error(s), {wc} warning(s), {ic} info)")
    lines.append("")

    stats = analysis.get("statistics", {}) or {}

    # Memory
    mem = stats.get("memory", {})
    if mem:
        lines.append("[Memory]")
        total = mem.get("total", 0)
        used = mem.get("used", 0)
        free = mem.get("free", 0)
        util = mem.get("utilization", 0.0)
        lines.append(f"  Total: {_fmt_size(total)}  |  Used: {_fmt_size(used)} ({util:.1%})  |  Free: {_fmt_size(free)}")
        lines.append(f"  Free fragments: {mem.get('fragment_count', 0)}  |  Largest: {_fmt_size(mem.get('largest_fragment', 0))}")
        lines.append("")

    # Processes
    pr = stats.get("processes", {})
    if pr:
        lines.append("[Processes]")
        lines.append(f"  Processes: {pr.get('process_count', 0)}  |  Threads: {pr.get('thread_count', 0)}")
        by_state = pr.get("by_state", {})
        if by_state:
            states = ", ".join(f"{k}: {v}" for k, v in sorted(by_state.items()))
            lines.append(f"  Process states: {states}")
        tbs = pr.get("thread_by_state", {})
        if tbs:
            tstates = ", ".join(f"{k}: {v}" for k, v in sorted(tbs.items()))
            lines.append(f"  Thread states: {tstates}")
        lines.append("")

    # Objects
    ob = stats.get("objects", {})
    if ob:
        lines.append("[Kernel Objects]")
        lines.append(f"  Count: {ob.get('object_count', 0)}")
        by_type = ob.get("by_type", {})
        if by_type:
            types = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items()))
            lines.append(f"  By type: {types}")
        lines.append("")

    # IPC
    ipc = stats.get("ipc", {})
    if ipc:
        lines.append("[IPC]")
        lines.append(f"  Endpoints: {ipc.get('endpoint_count', 0)}  |  Messages: {ipc.get('message_count', 0)}  |  Utilization: {ipc.get('queue_utilization', 0.0):.1%}")
        lines.append("")

    # Resources
    rs = stats.get("resources", {})
    if rs:
        lines.append("[Resources]")
        lines.append(f"  Count: {rs.get('resource_count', 0)}")
        by_type = rs.get("by_type", {})
        if by_type:
            types = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items()))
            lines.append(f"  By type: {types}")
        lines.append("")

    # Diagnostics
    diags = analysis.get("diagnostics", []) or []
    lines.append(f"[Diagnostics: {len(diags)}]")
    if not diags:
        lines.append("  No issues found.")
    else:
        lines.append(f"  Errors: {ec}  |  Warnings: {wc}  |  Info: {ic}")
        lines.append("")
        for d in diags:
            sev = d.get("severity", "?").upper()
            code = d.get("code", "?")
            msg = d.get("message", "")
            frag = d.get("fragment", "?")
            lines.append(f"  {sev} {code}: {msg} (fragment={frag})")
            ev = d.get("evidence")
            if ev:
                lines.append(f"    evidence: {json.dumps(ev, sort_keys=True)}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines) + "\n"


def _fmt_size(n: int) -> str:
    """Format a byte/unit count into a human-readable string."""
    if n < 0:
        return str(n)
    if n < 1024:
        return str(n)
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"
