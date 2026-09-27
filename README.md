# OS5 Micro — Fragment Analyzer

A **read-only diagnostic analyzer** for OS5 microkernel runtime state. Feed it a JSON snapshot describing memory layout, processes, threads, kernel objects, IPC channels, and resources — it reports fragmentation metrics, consistency violations, and structural anomalies.

## Quick Start

```bash
# Install in dev mode
pip install -e .

# Analyze a snapshot via CLI
os5 analyze examples/snapshot.json --json

# Launch the dashboard
pip install streamlit pandas
streamlit run dashboard/app.py
```

## What It Does

| Category | What It Checks |
|----------|---------------|
| **Memory** | Fragmentation ratio, overlapping regions, invalid ranges, duplicate IDs |
| **Processes** | Orphan parent references, dangling thread claims, duplicate PIDs |
| **Kernel Objects** | Negative refcounts, refcount ↔ reference list mismatches, unknown owners |
| **IPC** | Queue overflow (messages > capacity), depth mismatches, unknown endpoints |
| **Resources** | Duplicate resource IDs, ownership by nonexistent processes |
| **Cross-module** | Process → resource/IPC/thread back-reference consistency |

## Architecture

```
JSON Snapshot → snapshot.py (parser)
                    ↓
            FragmentAnalyzer.analyze()
            ├── memory.py       → fragmentation metrics
            ├── process.py      → process/thread validation
            ├── kobjects.py     → kernel object checks
            ├── ipc.py          → IPC queue analysis
            └── resources.py    → resource ownership
                    ↓
            consistency.py → cross-module checks
                    ↓
            statistics.py  → aggregate counters
                    ↓
            report.py      → JSON / text output
```

## CLI Usage

```bash
# Full analysis (text output)
os5 analyze examples/snapshot.json

# JSON output
os5 analyze examples/snapshot.json --json

# Diagnostics only
os5 analyze examples/snapshot.json --diagnostics

# Analyze specific modules
os5 analyze examples/snapshot.json --memory --processes

# Save to file
os5 analyze examples/snapshot.json --json --output result.json
```

## Dashboard

The Streamlit dashboard provides interactive visualization of analysis results:

- **Health status banner** — green/red indicator with error counts
- **Visual memory map** — address-space layout colored by state
- **Fragmentation gauge** — percentage indicator with progress bar
- **Process/thread tables** — state distribution charts
- **Per-endpoint IPC details** — capacity usage bars
- **Diagnostic browser** — grouped by code, with severity badges and evidence
- **Export** — download results as JSON or text report

```bash
streamlit run dashboard/app.py
```

## Example Snapshots

| File | Description |
|------|-------------|
| `snapshot.json` | Simple healthy system (1 process, 6 regions) |
| `healthy_multi_process.json` | 3 processes with varied resource types |
| `corrupted_system.json` | All diagnostic categories triggered (19 issues) |
| `high_fragmentation.json` | Extreme memory fragmentation (86.4%) |
| `empty_minimal.json` | Edge case: zero entities |
| `large_scale.json` | 5 processes, 10 threads, 6 kernel objects |

Pre-computed outputs are in `examples/outputs/`.

## Testing

```bash
pip install pytest
pytest
```

## Security Boundary

- **Read-only** — no kill/free/delete/modify operations
- **No host introspection** — CLI rejects `/proc`, `/sys`, `/dev`, `C:\Windows`
- **No network access** — fully offline and deterministic
- **No elevated privileges** — no root/admin required

See [docs/SECURITY_BOUNDARY.md](docs/SECURITY_BOUNDARY.md) for details.

## License

Internal / proprietary.
