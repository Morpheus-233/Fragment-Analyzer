# OS5 Fragment Analyzer — Security Boundary

> Required by spec section 56. This document is normative for the
> `os5-micro` repository scope (`<OS5_REPOSITORY_ROOT>` = this repo).

- The analyzer is **read-only**. It exposes `inspect / analyze / validate /
  report / dump / statistics` only. There are no `kill / free / delete /
  modify / mount / unmount / reconfigure / reset` operations.
- The analyzer analyzes **OS5 snapshot state** (explicitly supplied JSON:
  `snapshot_id, memory_regions, processes, threads, kernel_objects,
  ipc_endpoints, resources, metadata`). Synthetic example:
  `examples/snapshot.json`.
- The analyzer does **not** inspect arbitrary host state: no `/`, `/etc`,
  `/proc`, `/sys`, `/dev`, home-directory, or registry scans. The CLI
  rejects host scopes (`/` `/proc` `/sys` `/dev` `/etc` …, `C:\Windows` …).
- The analyzer does **not** modify host OS files, boot config, drivers,
  disks, or devices, and never formats/mounts/repartitions hardware.
- The analyzer does **not** require administrator / root / sudo privileges.
- The analyzer does **not** access arbitrary host memory (no raw pointer
  following; snapshot IDs/handles only) or physical disks.
- The analyzer does **not** send OS5 data externally: no network access,
  fully local and deterministic (`analyze(snapshot)` is a pure function of
  its input; no timestamps/randomness/host env in output).
- Temporary files, if any, live project-local (e.g. `OS5_REPO/.tmp/`) and
  cleanup removes only analyzer-created files.

## Repository architecture note (spec section 63)

The pre-existing repo contained **no** kernel, memory manager, process
table, IPC, or filesystem — only a source-code fragment model
(`src/os5/fragment/models.py`, preserved untouched). The `snapshot.py`
abstraction in this implementation is therefore the smallest new
project-local OS5 component needed for future kernel integration, via
narrow read-only snapshot getters (`analyzer_get_*_snapshot` style).
