"""OS5 Fragment Analyzer dashboard (read-only visualization layer).

Run from the repository root:

    streamlit run dashboard/app.py

The dashboard imports the real analyzer (`FragmentAnalyzer`) and only
visualizes its result dict. It never probes the host, never mutates
anything, and performs no network access.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from os5.fragment.analyzer import AnalyzerConfig, FragmentAnalyzer  # noqa: E402
from os5.fragment.defrag import simulate_defrag  # noqa: E402
from os5.fragment.report import to_json, to_text  # noqa: E402

EXAMPLES_DIR = REPO_ROOT / "examples"

st.set_page_config(
    page_title="OS5 Fragment Analyzer",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------
st.markdown("""
<style>
    /* Card & container styling */
    .metric-card {
        background: #21252b;
        border: 1px solid #3e4451;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 8px;
    }
    
    /* Status banner */
    .status-healthy {
        background: linear-gradient(135deg, #1a3a2a 0%, #1e3a1e 100%);
        border: 1px solid #2d5a3d;
        border-radius: 8px;
        padding: 16px 24px;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .status-error {
        background: linear-gradient(135deg, #3a1a1a 0%, #3a1e1e 100%);
        border: 1px solid #5a2d2d;
        border-radius: 8px;
        padding: 16px 24px;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        gap: 12px;
    }
    .status-text-ok { color: #98c379; font-size: 18px; font-weight: 600; }
    .status-text-err { color: #e06c75; font-size: 18px; font-weight: 600; }
    .status-sub { color: #abb2bf; font-size: 13px; margin-top: 2px; }

    /* Severity badges */
    .badge-error {
        background: #e06c75; color: #282c34; padding: 2px 8px;
        border-radius: 4px; font-size: 11px; font-weight: 600;
        display: inline-block;
    }
    .badge-warning {
        background: #e5c07b; color: #282c34; padding: 2px 8px;
        border-radius: 4px; font-size: 11px; font-weight: 600;
        display: inline-block;
    }
    .badge-info {
        background: #61afef; color: #282c34; padding: 2px 8px;
        border-radius: 4px; font-size: 11px; font-weight: 600;
        display: inline-block;
    }

    /* Gauge containers */
    .gauge-container {
        text-align: center;
        padding: 8px;
    }
    .gauge-value {
        font-size: 36px;
        font-weight: 700;
        color: #abb2bf;
        line-height: 1.2;
    }
    .gauge-label {
        font-size: 12px;
        color: #636d83;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-top: 4px;
    }

    /* Memory map blocks */
    .mem-block {
        display: inline-block;
        height: 38px;
        border-radius: 3px;
        position: relative;
        transition: opacity 0.2s;
        min-width: 4px;
    }
    .mem-block:hover {
        opacity: 0.85;
        outline: 2px solid #ffffff;
    }
    .mem-block-overlap {
        background: repeating-linear-gradient(
            45deg,
            #e06c75,
            #e06c75 6px,
            #be5059 6px,
            #be5059 12px
        ) !important;
    }
    .mem-block-hole {
        background: repeating-linear-gradient(
            -45deg,
            #21252b,
            #21252b 5px,
            #2c313a 5px,
            #2c313a 10px
        ) !important;
        border: 1px dashed #4b5263;
    }
    .mem-row {
        display: flex;
        gap: 2px;
        border-radius: 6px;
        overflow-x: auto;
        background: #1e2127;
        padding: 4px;
        width: 100%;
        align-items: center;
    }

    /* Tree card */
    .tree-card {
        background: #21252b;
        border-left: 3px solid #61afef;
        padding: 10px 14px;
        margin-bottom: 8px;
        border-radius: 0 6px 6px 0;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _discover_examples() -> list[str]:
    """List all .json files in the examples/ directory."""
    if not EXAMPLES_DIR.is_dir():
        return []
    return sorted(f.name for f in EXAMPLES_DIR.glob("*.json") if f.is_file())


@st.cache_data
def _load_snapshot(name: str) -> dict:
    p = EXAMPLES_DIR / name
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _safe_int(v: object, default: int = 0) -> int:
    """Lenient int coercion for raw snapshot values; never raises."""
    try:
        if isinstance(v, bool):
            return int(v)
        if isinstance(v, float):
            return int(v) if v == v and abs(v) != float("inf") else default
        return int(str(v).strip()) if not isinstance(v, int) else v
    except Exception:
        return default


def _safe_float(v: object, default: float = 0.0) -> float:
    try:
        f = float(v)  # type: ignore[arg-type]
        return f if f == f and abs(f) != float("inf") else default
    except Exception:
        return default


@st.cache_data
def _analyze(snapshot_json: str, include: tuple) -> dict:
    try:
        snapshot = json.loads(snapshot_json)
    except Exception:
        snapshot = {}
    cfg = AnalyzerConfig(
        include_memory="memory" in include,
        include_processes="processes" in include,
        include_objects="objects" in include,
        include_ipc="ipc" in include,
        include_resources="resources" in include,
    )
    return FragmentAnalyzer(cfg).analyze(snapshot)


def _fmt_size(n: int | float) -> str:
    n = _safe_int(n)
    if n < 0:
        return str(n)
    if n < 1024:
        return f"{n} B" if n > 0 else "0 B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024):.1f} MB"
    return f"{n / (1024 * 1024 * 1024):.1f} GB"


def _fmt_hex(n: int | float) -> str:
    return f"0x{_safe_int(n):04X}"


def _severity_badge(sev: str) -> str:
    cls = {"error": "badge-error", "warning": "badge-warning", "info": "badge-info"}.get(sev.lower(), "badge-info")
    return f'<span class="{cls}">{sev.upper()}</span>'


def _frag_detail(result: dict, ftype: str) -> dict:
    for frag in result.get("fragments", []) or []:
        if frag.get("type") == ftype:
            return frag.get("summary", {}) or {}
    return {}


def _color_for_state(state: str) -> str:
    return {
        "allocated": "#61afef",
        "free": "#98c379",
        "reserved": "#e5c07b",
    }.get(state.lower(), "#636d83")


def _layout_bar_html(valid_regions: list, overlap_ids: set | None = None) -> tuple:
    """Render address-space blocks for pre-sorted valid regions.

    Returns (bar_html, min_addr, max_addr, span). Pure function of its
    input; used for both the current layout and the defrag projection.
    """
    overlap_ids = overlap_ids or set()
    sorted_regs = sorted(valid_regions, key=lambda x: _safe_int(x.get("start", 0)))
    min_addr = _safe_int(sorted_regs[0].get("start", 0))
    max_addr = max(_safe_int(r.get("end", 0)) for r in sorted_regs)
    addr_span = max(1, max_addr - min_addr)
    blocks_html = ""
    cur_pos = min_addr
    for r in sorted_regs:
        s = _safe_int(r.get("start", 0))
        e = _safe_int(r.get("end", 0))
        sz = max(0, e - s)
        rid = str(r.get("id", "?"))
        st_val = str(r.get("state", "unknown"))
        if s > cur_pos:
            hole_size = s - cur_pos
            hole_pct = max(1.0, (hole_size / addr_span) * 100)
            blocks_html += (
                f'<div class="mem-block mem-block-hole" style="width:{hole_pct:.1f}%;" '
                f'title="Unmapped Gap [{_fmt_hex(cur_pos)} - {_fmt_hex(s)}) — {_fmt_size(hole_size)}"></div>'
            )
        pct = max(1.5, (sz / addr_span) * 100)
        is_overlap = rid in overlap_ids
        overlap_cls = " mem-block-overlap" if is_overlap else ""
        color = "#e06c75" if is_overlap else _color_for_state(st_val)
        blocks_html += (
            f'<div class="mem-block{overlap_cls}" style="width:{pct:.1f}%;background:{color};" '
            f'title="{rid}: [{_fmt_hex(s)} - {_fmt_hex(e)}) {st_val} — {_fmt_size(sz)} ({sz} bytes)"></div>'
        )
        cur_pos = max(cur_pos, e)
    return f'<div class="mem-row">{blocks_html}</div>', min_addr, max_addr, addr_span


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
examples = _discover_examples()

with st.sidebar:
    st.markdown("### 🔬 OS5 Fragment Analyzer")
    st.caption("Microkernel Runtime Diagnostic Observer")
    st.divider()

    st.markdown("**Snapshot Source**")
    source_mode = st.radio(
        "Load from",
        options=["Example library", "Upload file", "Live Sandbox"],
        horizontal=True,
        label_visibility="collapsed",
    )

    selected_example = None
    uploaded = None

    if source_mode == "Example library" and examples:
        default_idx = examples.index("snapshot.json") if "snapshot.json" in examples else 0
        selected_example = st.selectbox(
            "Select snapshot",
            options=examples,
            index=default_idx,
        )
    elif source_mode == "Upload file":
        uploaded = st.file_uploader("Upload snapshot JSON", type=["json"])

    st.divider()
    st.markdown("**Analyzer Modules**")
    include = st.pills(
        "Modules",
        options=["memory", "processes", "objects", "ipc", "resources"],
        default=["memory", "processes", "objects", "ipc", "resources"],
        selection_mode="multi",
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("**Diagnostic Filter**")
    sev_filter = st.segmented_control(
        "Severity",
        options=["all", "error", "warning", "info"],
        default="all",
        label_visibility="collapsed",
    )


# ---------------------------------------------------------------------------
# State Management & Loading
# ---------------------------------------------------------------------------
if "snapshot" not in st.session_state:
    st.session_state.snapshot = _load_snapshot(examples[0]) if examples else {}
    st.session_state.snapshot_name = examples[0] if examples else "empty"
    st.session_state.sandbox_json = json.dumps(st.session_state.snapshot, indent=2)

if source_mode == "Example library" and selected_example:
    if st.session_state.get("current_source_mode") != "Example library" or st.session_state.snapshot_name != selected_example:
        st.session_state.snapshot = _load_snapshot(selected_example)
        st.session_state.snapshot_name = selected_example
        st.session_state.sandbox_json = json.dumps(st.session_state.snapshot, indent=2)

elif source_mode == "Upload file" and uploaded is not None:
    try:
        data = json.loads(uploaded.getvalue().decode("utf-8"))
        if isinstance(data, dict):
            st.session_state.snapshot = data
            st.session_state.snapshot_name = uploaded.name
            st.session_state.sandbox_json = json.dumps(data, indent=2)
        else:
            st.sidebar.error("Snapshot must be a JSON object.")
    except Exception as exc:
        st.sidebar.error(f"Invalid JSON: {exc}")

st.session_state.current_source_mode = source_mode
snapshot = st.session_state.snapshot
snapshot_json = json.dumps(snapshot, sort_keys=True)

# ---------------------------------------------------------------------------
# Analyze (Guarded against None pills)
# ---------------------------------------------------------------------------
active_modules = tuple(sorted(include or []))
result = _analyze(snapshot_json, active_modules)
stats = result.get("statistics", {}) or {}
meta = result.get("metadata", {}) or {}
mem_stats = stats.get("memory", {}) or {}
mem_detail = _frag_detail(result, "memory")
proc_stats = stats.get("processes", {}) or {}
obj_stats = stats.get("objects", {}) or {}
ipc_stats = stats.get("ipc", {}) or {}
res_stats = stats.get("resources", {}) or {}
diags = result.get("diagnostics", []) or []

consistent = result.get("consistent", True)
ec = meta.get("error_count", sum(1 for d in diags if d.get("severity") == "error"))
wc = meta.get("warning_count", sum(1 for d in diags if d.get("severity") == "warning"))
ic = meta.get("info_count", sum(1 for d in diags if d.get("severity") == "info"))

# ---------------------------------------------------------------------------
# Header + Status Banner
# ---------------------------------------------------------------------------
col_head1, col_head2 = st.columns([3, 1])
with col_head1:
    st.markdown(f"### Snapshot: `{st.session_state.snapshot_name}`")
with col_head2:
    st.caption(f"Modules active: {len(active_modules)}/5")

if consistent:
    st.markdown(
        '<div class="status-healthy">'
        '<div><span class="status-text-ok">✓ System Healthy</span>'
        '<div class="status-sub">All consistency checks passed — no structural anomalies or resource collisions detected.</div>'
        '</div></div>',
        unsafe_allow_html=True,
    )
else:
    st.markdown(
        f'<div class="status-error">'
        f'<div><span class="status-text-err">✗ {ec} Error{"s" if ec != 1 else ""} Detected</span>'
        f'<div class="status-sub">{ec} error(s), {wc} warning(s), {ic} info — see Diagnostics tab for evidence and details.</div>'
        f'</div></div>',
        unsafe_allow_html=True,
    )

# ---------------------------------------------------------------------------
# KPI Row
# ---------------------------------------------------------------------------
with st.container(horizontal=True):
    total_mem = mem_stats.get("total", 0)
    used_mem = mem_stats.get("used", 0)
    free_mem = mem_stats.get("free", 0)
    util = mem_stats.get("utilization", 0.0)
    frag_count = mem_stats.get("fragment_count", 0)
    ext_frag = float(mem_detail.get("external_fragmentation", 0.0))

    st.metric("Total Memory", _fmt_size(total_mem), border=True)
    st.metric("Used", _fmt_size(used_mem), delta=f"{util:.0%} utilized", border=True)
    st.metric("Free", _fmt_size(free_mem), delta=f"{ext_frag:.0%} ext frag", delta_color="inverse", border=True)
    st.metric("Free Fragments", str(frag_count), border=True)
    st.metric("Processes", str(proc_stats.get("process_count", 0)), border=True)
    st.metric("Threads", str(proc_stats.get("thread_count", 0)), border=True)

# ---------------------------------------------------------------------------
# Tabs Navigation
# ---------------------------------------------------------------------------
if sev_filter != "all":
    diags_filtered = [d for d in diags if d.get("severity") == sev_filter]
else:
    diags_filtered = diags

tab_names = [
    "🗺️ Memory Map",
    "⚙️ Processes & Hierarchy",
    "🧊 Objects",
    "📡 IPC",
    "📁 Resources",
    f"🩺 Diagnostics ({len(diags_filtered)})",
    "⚖️ Compare Snapshots",
    "🧪 Live Sandbox",
    "📥 Export",
]
mem_tab, proc_tab, obj_tab, ipc_tab, res_tab, diag_tab, compare_tab, sandbox_tab, export_tab = st.tabs(tab_names)

# ===========================================================================
# 1. MEMORY TAB
# ===========================================================================
with mem_tab:
    regions = snapshot.get("memory_regions", []) or []
    if "memory" not in active_modules:
        st.info("Memory analyzer module is disabled — enable it in the sidebar under Analyzer Modules.")
    elif not regions:
        st.info("No memory regions defined in this snapshot.")
    else:
        # Overlap ids feed the Region Inventory "Collision" column and the
        # striped overlap highlighting in the layout bar.
        overlap_diags = [d for d in diags if d.get("code") == "FRAG003"]
        overlap_region_ids = set()
        for od in overlap_diags:
            ev = od.get("evidence", {})
            if "region_a" in ev:
                overlap_region_ids.add(ev["region_a"].get("id"))
            if "region_b" in ev:
                overlap_region_ids.add(ev["region_b"].get("id"))

        with st.container(border=True):
            st.markdown("**Address Space Physical Layout**")
            valid_regions = [r for r in regions
                             if isinstance(r, dict)
                             and _safe_int(r.get("end"), -1) > _safe_int(r.get("start"), 0)]

            if overlap_diags:
                st.warning(f"⚠️ **{len(overlap_diags)} Memory Collision(s) Detected:** Overlapping regions highlighted in striped red.")

            if valid_regions:
                bar_html, min_addr, max_addr, addr_span = _layout_bar_html(valid_regions, overlap_region_ids)
                st.markdown(bar_html, unsafe_allow_html=True)
                st.caption(f"Address Range: `{_fmt_hex(min_addr)}` ({min_addr}) ➔ `{_fmt_hex(max_addr)}` ({max_addr}) | Span: `{_fmt_size(addr_span)}`")

                # Legend
                leg1, leg2, leg3, leg4, leg5 = st.columns(5)
                with leg1:
                    st.markdown('<span style="color:#61afef;">■</span> **Allocated**', unsafe_allow_html=True)
                with leg2:
                    st.markdown('<span style="color:#98c379;">■</span> **Free**', unsafe_allow_html=True)
                with leg3:
                    st.markdown('<span style="color:#e5c07b;">■</span> **Reserved**', unsafe_allow_html=True)
                with leg4:
                    st.markdown('<span style="color:#e06c75;">▨</span> **Collision / Overlap**', unsafe_allow_html=True)
                with leg5:
                    st.markdown('<span style="color:#4b5263;">▨</span> **Unmapped Hole**', unsafe_allow_html=True)

        col_m1, col_m2 = st.columns(2)
        with col_m1:
            with st.container(border=True):
                st.markdown("**Region Inventory**")
                df_rows = []
                for r in regions:
                    if not isinstance(r, dict):
                        continue
                    s = _safe_int(r.get("start", 0))
                    e = _safe_int(r.get("end", 0))
                    rid = str(r.get("id", "?"))
                    df_rows.append({
                        "Region": rid,
                        "Start": f"{_fmt_hex(s)} ({s})",
                        "End": f"{_fmt_hex(e)} ({e})",
                        "Size": _fmt_size(max(0, e - s)),
                        "State": str(r.get("state", "unknown")),
                        "Kind": str(r.get("kind", "unknown")),
                        "Owner": str(r.get("owner_id", "—") or "—"),
                        "Collision": "⚠️ YES" if rid in overlap_region_ids else "NO",
                    })
                df = pd.DataFrame(df_rows)
                st.dataframe(df, hide_index=True)

        with col_m2:
            with st.container(border=True):
                st.markdown("**Fragmentation Gauge & Metrics**")
                frag_pct = int(ext_frag * 100)
                color = "#98c379" if frag_pct < 30 else "#e5c07b" if frag_pct < 70 else "#e06c75"
                st.markdown(
                    f'<div class="gauge-container">'
                    f'<div class="gauge-value" style="color:{color};">{frag_pct}%</div>'
                    f'<div class="gauge-label">External Fragmentation Index</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.progress(min(max(ext_frag, 0.0), 1.0))

                frag_data = {
                    "Metric": ["Free fragments", "Largest contiguous free", "Smallest free", "Average free", "Address space utilization"],
                    "Value": [
                        str(mem_detail.get("free_fragments", frag_count)),
                        _fmt_size(mem_detail.get("largest_free", mem_stats.get("largest_fragment", 0))),
                        _fmt_size(mem_detail.get("smallest_free", 0)),
                        _fmt_size(int(mem_detail.get("average_free", 0))),
                        f"{util:.1%}",
                    ],
                }
                st.table(frag_data)

        with st.container(border=True):
            st.markdown("**Defragmentation Projection**")
            st.caption("What-if simulation only — the analyzer is read-only and no OS state is modified.")
            show_defrag = st.checkbox("Show defragmented projection", key="show_defrag")
            if show_defrag:
                projected = simulate_defrag(snapshot if isinstance(snapshot, dict) else {})
                proj_result = _analyze(json.dumps(projected, sort_keys=True), active_modules)
                proj_mem = (proj_result.get("statistics", {}) or {}).get("memory", {}) or {}
                proj_detail = _frag_detail(proj_result, "memory")
                st.table(
                    {
                        "Metric": ["Free fragments", "Largest free", "External fragmentation"],
                        "Current": [
                            str(mem_stats.get("fragment_count", 0)),
                            _fmt_size(mem_stats.get("largest_fragment", 0)),
                            f"{_safe_float(mem_detail.get('external_fragmentation', 0.0)):.1%}",
                        ],
                        "Projected": [
                            str(proj_mem.get("fragment_count", 0)),
                            _fmt_size(proj_mem.get("largest_fragment", 0)),
                            f"{_safe_float(proj_detail.get('external_fragmentation', 0.0)):.1%}",
                        ],
                    }
                )
                proj_regs = [r for r in (projected.get("memory_regions", []) or [])
                             if isinstance(r, dict)
                             and _safe_int(r.get("end"), -1) > _safe_int(r.get("start"), 0)]
                if proj_regs:
                    proj_html, _, _, _ = _layout_bar_html(proj_regs)
                    st.markdown(proj_html, unsafe_allow_html=True)

# ===========================================================================
# 2. PROCESSES & HIERARCHY TAB
# ===========================================================================
with proc_tab:
    plist = snapshot.get("processes", []) or []
    tlist = snapshot.get("threads", []) or []
    if "processes" not in active_modules:
        st.info("Processes analyzer module is disabled — enable it in the sidebar under Analyzer Modules.")
    elif not plist and not tlist:
        st.info("No processes or threads present in this snapshot.")
    else:
        col_p1, col_p2 = st.columns(2)
        with col_p1:
            with st.container(border=True):
                st.markdown("**Process State Distribution**")
                by_state = proc_stats.get("by_state", {})
                if by_state:
                    state_df = pd.DataFrame([{"State": k, "Count": v} for k, v in sorted(by_state.items())])
                    st.bar_chart(state_df, x="State", y="Count", color="State")
                else:
                    st.metric("Processes", "0")

        with col_p2:
            with st.container(border=True):
                st.markdown("**Thread State Distribution**")
                tbs = proc_stats.get("thread_by_state", {})
                if tbs:
                    tstate_df = pd.DataFrame([{"State": k, "Count": v} for k, v in sorted(tbs.items())])
                    st.bar_chart(tstate_df, x="State", y="Count", color="State")
                else:
                    st.metric("Threads", "0")

        with st.container(border=True):
            st.markdown("**Process Hierarchy & Resource Bindings**")
            # Map threads to processes
            threads_by_owner: dict[str, list] = {}
            for t in tlist:
                if isinstance(t, dict):
                    op = str(t.get("owner_pid", "none") or "none")
                    threads_by_owner.setdefault(op, []).append(t)

            for p in plist:
                if not isinstance(p, dict):
                    continue
                pid = str(p.get("pid", p.get("id", "?")))
                pst = str(p.get("state", "unknown"))
                parent = str(p.get("parent_pid", "—") or "—")
                claimed_threads = list(p.get("thread_ids", []) or [])
                actual_threads = threads_by_owner.get(pid, [])
                claimed_res = list(p.get("resource_ids", []) or [])
                claimed_ipc = list(p.get("ipc_endpoint_ids", []) or [])

                with st.expander(f"📁 Process **`{pid}`** ({pst.upper()}) — Priority: {p.get('priority', 0)} | Parent: `{parent}`"):
                    c1, c2, c3 = st.columns(3)
                    with c1:
                        st.markdown(f"**Threads ({len(actual_threads)})**")
                        if actual_threads:
                            for at in actual_threads:
                                tid = at.get("tid", "?")
                                t_st = at.get("state", "unknown")
                                st.markdown(f"- Thread `{tid}` ({t_st})")
                        else:
                            st.caption("No threads assigned")
                        if set(claimed_threads) != {t.get("tid") for t in actual_threads}:
                            st.caption(f"Declared thread IDs: {claimed_threads}")

                    with c2:
                        st.markdown(f"**IPC Endpoints ({len(claimed_ipc)})**")
                        if claimed_ipc:
                            for ep in claimed_ipc:
                                st.markdown(f"- Endpoint `{ep}`")
                        else:
                            st.caption("None")

                    with c3:
                        st.markdown(f"**Resources ({len(claimed_res)})**")
                        if claimed_res:
                            for res in claimed_res:
                                st.markdown(f"- Resource `{res}`")
                        else:
                            st.caption("None")

# ===========================================================================
# 3. KERNEL OBJECTS TAB
# ===========================================================================
with obj_tab:
    kobjects = snapshot.get("kernel_objects", []) or []
    if "objects" not in active_modules:
        st.info("Objects analyzer module is disabled — enable it in the sidebar under Analyzer Modules.")
    elif not kobjects:
        st.info("No kernel objects present in this snapshot.")
    else:
        col_o1, col_o2 = st.columns([1, 1])
        with col_o1:
            with st.container(border=True):
                st.markdown("**Objects by Type**")
                by_type = obj_stats.get("by_type", {})
                if by_type:
                    type_df = pd.DataFrame([{"Type": k, "Count": v} for k, v in sorted(by_type.items())])
                    st.bar_chart(type_df, x="Type", y="Count", color="Type")

        with col_o2:
            with st.container(border=True):
                st.markdown("**Summary**")
                st.metric("Total Kernel Objects", str(obj_stats.get("object_count", len(kobjects))), border=True)
                types_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items())) if by_type else "None"
                st.caption(f"Active object types: {types_str}")

        with st.container(border=True):
            st.markdown("**Kernel Object Table**")
            obj_rows = []
            for idx, o in enumerate(kobjects):
                if not isinstance(o, dict):
                    continue
                oid = str(o.get("obj_id", o.get("id", f"obj-{idx}")))
                rc = o.get("refcount", 0)
                refs = o.get("references", []) or []
                refs = list(refs) if isinstance(refs, (list, tuple)) else []
                ref_names = [str(x) for x in refs]
                rc_mismatch = (len(ref_names) > 0 and _safe_int(rc, 0) != len(ref_names)) or _safe_int(rc, 0) < 0
                obj_rows.append({
                    "Object ID": oid,
                    "Type": str(o.get("obj_type", "generic")),
                    "Owner": str(o.get("owner_id", "—") or "—"),
                    "State": str(o.get("state", "unknown")),
                    "Refcount": str(rc),
                    "Reference List": ", ".join(ref_names) if ref_names else "—",
                    "Anomaly": "⚠️ YES" if rc_mismatch else "OK",
                })
            st.dataframe(pd.DataFrame(obj_rows), hide_index=True)

# ===========================================================================
# 4. IPC TAB
# ===========================================================================
with ipc_tab:
    eps = snapshot.get("ipc_endpoints", []) or []
    if "ipc" not in active_modules:
        st.info("IPC analyzer module is disabled — enable it in the sidebar under Analyzer Modules.")
    elif not eps:
        st.info("No IPC endpoints defined in this snapshot.")
    else:
        ipc_detail = _frag_detail(result, "ipc")
        ep_details = ipc_detail.get("endpoints", []) or []

        with st.container(horizontal=True):
            st.metric("Endpoints", str(ipc_stats.get("endpoint_count", len(eps))), border=True)
            st.metric("Total Messages", str(ipc_stats.get("message_count", 0)), border=True)
            q_util = ipc_stats.get("queue_utilization", 0.0)
            st.metric("Aggregate Queue Utilization", f"{q_util:.0%}", border=True)

        if ep_details:
            with st.container(border=True):
                st.markdown("**Endpoint Queue Utilization**")
                ep_rows = []
                for idx, ep in enumerate(ep_details):
                    eid = str(ep.get("ep_id", f"ep-{idx}"))
                    mc = _safe_int(ep.get("message_count", 0))
                    cap = _safe_int(ep.get("capacity", 0))
                    over = cap > 0 and mc > cap
                    ep_rows.append({
                        "Endpoint": f"{eid} ({ep.get('owner_id') or 'orphan'})",
                        "Used Messages": mc,
                        "Free Capacity": max(0, cap - mc),
                        "Capacity": cap,
                        "Utilization": f"{ep.get('utilization', 0.0):.0%}",
                        "State": str(ep.get("state", "unknown")),
                        "Over Capacity": "🚨 YES" if over else "NO",
                    })
                ep_df = pd.DataFrame(ep_rows)
                st.dataframe(ep_df, hide_index=True)

                st.markdown("**Capacity vs Utilization Chart**")
                chart_cap_df = ep_df[["Endpoint", "Used Messages", "Free Capacity"]]
                st.bar_chart(chart_cap_df, x="Endpoint", y=["Used Messages", "Free Capacity"], stack=True)

# ===========================================================================
# 5. RESOURCES TAB
# ===========================================================================
with res_tab:
    resources = snapshot.get("resources", []) or []
    if "resources" not in active_modules:
        st.info("Resources analyzer module is disabled — enable it in the sidebar under Analyzer Modules.")
    elif not resources:
        st.info("No resources defined in this snapshot.")
    else:
        col_r1, col_r2 = st.columns(2)
        with col_r1:
            with st.container(border=True):
                st.markdown("**Resources by Type**")
                by_type = res_stats.get("by_type", {})
                if by_type:
                    rtype_df = pd.DataFrame([{"Type": k, "Count": v} for k, v in sorted(by_type.items())])
                    st.bar_chart(rtype_df, x="Type", y="Count", color="Type")

        with col_r2:
            with st.container(border=True):
                st.markdown("**Summary**")
                st.metric("Total Resources", str(res_stats.get("resource_count", len(resources))), border=True)
                types_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_type.items())) if by_type else "None"
                st.caption(f"Allocated resource types: {types_str}")

        with st.container(border=True):
            st.markdown("**Resource Inventory**")
            res_df = pd.DataFrame([
                {
                    "Resource ID": str(r.get("res_id", r.get("id", "?"))),
                    "Type": str(r.get("res_type", "generic")),
                    "Owner": str(r.get("owner_id", "—") or "—"),
                    "State": str(r.get("state", "unknown")),
                }
                for r in resources if isinstance(r, dict)
            ])
            st.dataframe(res_df, hide_index=True)

# ===========================================================================
# 6. DIAGNOSTICS TAB
# ===========================================================================
with diag_tab:
    if not diags_filtered:
        if sev_filter == "all":
            st.success("✅ No diagnostics — snapshot is consistent.")
        else:
            st.info(f"No `{sev_filter}` diagnostics found. Try resetting the severity filter in the sidebar.")
    else:
        fec = sum(1 for d in diags_filtered if d.get("severity") == "error")
        fwc = sum(1 for d in diags_filtered if d.get("severity") == "warning")
        fic = sum(1 for d in diags_filtered if d.get("severity") == "info")
        with st.container(horizontal=True):
            if fec > 0:
                st.metric("Errors", str(fec), border=True)
            if fwc > 0:
                st.metric("Warnings", str(fwc), border=True)
            if fic > 0:
                st.metric("Info", str(fic), border=True)

        col_d1, col_d2 = st.columns([2, 1])
        with col_d1:
            search_query = st.text_input("🔍 Filter diagnostics by text or fragment", placeholder="e.g. r0, overflow, refcount")
        with col_d2:
            all_codes = sorted(list({d.get("code", "?") for d in diags_filtered}))
            selected_codes = st.multiselect("Filter by Code", options=all_codes, default=all_codes)

        display_diags = [
            d for d in diags_filtered
            if d.get("code") in selected_codes
            and (not search_query or search_query.lower() in json.dumps(d).lower())
        ]

        st.caption(f"Showing {len(display_diags)} of {len(diags)} total diagnostics")

        # Group by diagnostic code
        by_code: dict[str, list] = {}
        for d in display_diags:
            code = d.get("code", "?")
            by_code.setdefault(code, []).append(d)

        for code, items in sorted(by_code.items()):
            with st.expander(f"**{code}** — {len(items)} issue{'s' if len(items) != 1 else ''}", expanded=True):
                for d in items:
                    sev = d.get("severity", "?")
                    msg = d.get("message", "")
                    frag = d.get("fragment", "?")
                    badge = _severity_badge(sev)
                    st.markdown(f'{badge} **`{frag}`**: {msg}', unsafe_allow_html=True)
                    if d.get("evidence"):
                        st.json(d["evidence"])

# ===========================================================================
# 7. COMPARE SNAPSHOTS TAB
# ===========================================================================
with compare_tab:
    st.markdown("**Side-by-Side Snapshot Comparison**")
    st.caption("Compare the current snapshot with any other baseline snapshot to track changes, fragmentation, and resolved/introduced anomalies.")

    if not examples or len(examples) < 2:
        st.info("At least two snapshots are needed to compare.")
    else:
        cmp_col1, cmp_col2 = st.columns(2)
        with cmp_col1:
            snap_a_name = st.selectbox("Baseline Snapshot (A)", options=examples, index=0, key="cmp_a")
        with cmp_col2:
            default_b_idx = 1 if len(examples) > 1 else 0
            snap_b_name = st.selectbox("Comparison Snapshot (B)", options=examples, index=default_b_idx, key="cmp_b")

        snap_a = _load_snapshot(snap_a_name)
        snap_b = _load_snapshot(snap_b_name)

        res_a = _analyze(json.dumps(snap_a), active_modules)
        res_b = _analyze(json.dumps(snap_b), active_modules)

        stats_a = res_a.get("statistics", {}) or {}
        stats_b = res_b.get("statistics", {}) or {}
        mem_a = stats_a.get("memory", {}) or {}
        mem_b = stats_b.get("memory", {}) or {}
        meta_a = res_a.get("metadata", {}) or {}
        meta_b = res_b.get("metadata", {}) or {}

        # Comparison Metrics Table (all cells strings: pyarrow
        # rejects mixed str/int columns)
        st.markdown("#### High-Level Metrics Comparison")
        cmp_df = pd.DataFrame([
            {"Metric": "Consistent", f"A ({snap_a_name})": "YES" if res_a.get("consistent") else "NO", f"B ({snap_b_name})": "YES" if res_b.get("consistent") else "NO"},
            {"Metric": "Total Diagnostics", f"A ({snap_a_name})": str(len(res_a.get("diagnostics", []))), f"B ({snap_b_name})": str(len(res_b.get("diagnostics", [])))},
            {"Metric": "Errors", f"A ({snap_a_name})": str(meta_a.get("error_count", 0)), f"B ({snap_b_name})": str(meta_b.get("error_count", 0))},
            {"Metric": "Warnings", f"A ({snap_a_name})": str(meta_a.get("warning_count", 0)), f"B ({snap_b_name})": str(meta_b.get("warning_count", 0))},
            {"Metric": "Memory Total", f"A ({snap_a_name})": _fmt_size(mem_a.get("total", 0)), f"B ({snap_b_name})": _fmt_size(mem_b.get("total", 0))},
            {"Metric": "Memory Used", f"A ({snap_a_name})": _fmt_size(mem_a.get("used", 0)), f"B ({snap_b_name})": _fmt_size(mem_b.get("used", 0))},
            {"Metric": "Memory Free", f"A ({snap_a_name})": _fmt_size(mem_a.get("free", 0)), f"B ({snap_b_name})": _fmt_size(mem_b.get("free", 0))},
            {"Metric": "Free Fragments", f"A ({snap_a_name})": str(mem_a.get("fragment_count", 0)), f"B ({snap_b_name})": str(mem_b.get("fragment_count", 0))},
            {"Metric": "Processes", f"A ({snap_a_name})": str(stats_a.get("processes", {}).get("process_count", 0)), f"B ({snap_b_name})": str(stats_b.get("processes", {}).get("process_count", 0))},
            {"Metric": "IPC Endpoints", f"A ({snap_a_name})": str(stats_a.get("ipc", {}).get("endpoint_count", 0)), f"B ({snap_b_name})": str(stats_b.get("ipc", {}).get("endpoint_count", 0))},
        ])
        st.dataframe(cmp_df, hide_index=True)

# ===========================================================================
# 8. LIVE SANDBOX & JSON EDITOR
# ===========================================================================
with sandbox_tab:
    st.markdown("**Live Snapshot Sandbox & JSON Editor**")
    st.caption("Modify snapshot JSON live, inject memory regions or faulty states, and observe instant re-analysis.")

    sandbox_input = st.text_area(
        "Edit Snapshot JSON",
        value=st.session_state.sandbox_json,
        height=320,
    )

    s_col1, s_col2 = st.columns([1, 4])
    with s_col1:
        if st.button("⚡ Apply & Re-Analyze", type="primary"):
            try:
                parsed = json.loads(sandbox_input)
                if isinstance(parsed, dict):
                    st.session_state.snapshot = parsed
                    st.session_state.snapshot_name = "sandbox-custom"
                    st.session_state.sandbox_json = sandbox_input
                    st.rerun()
                else:
                    st.error("JSON root must be an object { ... }")
            except Exception as e:
                st.error(f"Invalid JSON syntax: {e}")
    with s_col2:
        if st.button("🔄 Reset to Current Example"):
            if selected_example:
                st.session_state.snapshot = _load_snapshot(selected_example)
                st.session_state.snapshot_name = selected_example
                st.session_state.sandbox_json = json.dumps(st.session_state.snapshot, indent=2)
                st.rerun()

# ===========================================================================
# 9. EXPORT TAB
# ===========================================================================
with export_tab:
    st.markdown("**Export Analysis Artifacts**")
    st.caption("Download complete deterministic report artifacts in structured JSON or plaintext format.")

    col_e1, col_e2 = st.columns(2)
    with col_e1:
        json_output = to_json(result)
        st.download_button(
            label="📥 Download JSON Report",
            data=json_output,
            file_name=f"os5_analysis_{result.get('snapshot_id', 'unknown')}.json",
            mime="application/json",
            width="stretch",
        )
    with col_e2:
        text_output = to_text(result)
        st.download_button(
            label="📄 Download Text Summary",
            data=text_output,
            file_name=f"os5_analysis_{result.get('snapshot_id', 'unknown')}.txt",
            mime="text/plain",
            width="stretch",
        )

    with st.expander("Preview Plaintext Report"):
        st.code(text_output, language="text")

    with st.expander("Preview JSON Output"):
        st.code(json_output, language="json")
