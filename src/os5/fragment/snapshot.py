"""OS5 snapshot data model (project-local, read-only).

This module is a NEW minimal OS5 component (spec section 63): the repository
contained no kernel/memory/process structures, only a source-code fragment
model (models.py). This file defines the smallest snapshot abstraction the
Fragment Analyzer can observe without inventing a full OS.

Safety: plain dataclasses only. No host introspection, no I/O, no network,
no timestamps, no randomness. Snapshots are explicitly supplied OS5 data
(dump/trace/snapshot file), never host state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class FragmentType:
    MEMORY = "MEMORY"
    PROCESS = "PROCESS"
    THREAD = "THREAD"
    ADDRESS_SPACE = "ADDRESS_SPACE"
    MAPPING = "MAPPING"
    KERNEL_OBJECT = "KERNEL_OBJECT"
    IPC = "IPC"
    FILE = "FILE"
    RESOURCE = "RESOURCE"
    DEVICE = "DEVICE"


MEMORY_STATES = ("allocated", "free", "reserved")
MEMORY_KINDS = ("private", "shared")


@dataclass(frozen=True)
class MemoryRegion:
    id: str
    start: int
    end: int  # half-open [start, end)
    state: str = "allocated"
    kind: str = "private"
    perms: tuple = ("read",)
    owner_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "start": self.start, "end": self.end,
            "state": self.state, "kind": self.kind,
            "perms": list(self.perms), "owner_id": self.owner_id,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "MemoryRegion":
        try:
            perms = d.get("perms", ["read"])
            return MemoryRegion(
                id=str(d.get("id", "")),
                start=int(d.get("start", 0)),
                end=int(d.get("end", 0)),
                state=str(d.get("state", "allocated")),
                kind=str(d.get("kind", "private")),
                perms=tuple(perms) if isinstance(perms, list) else (str(perms),),
                owner_id=d.get("owner_id"),
            )
        except Exception:
            return MemoryRegion(id=str(d.get("id", "?")), start=0, end=0)


@dataclass(frozen=True)
class ProcessInfo:
    pid: str
    state: str = "unknown"
    parent_pid: Optional[str] = None
    thread_ids: tuple = ()
    address_space_id: Optional[str] = None
    resource_ids: tuple = ()
    ipc_endpoint_ids: tuple = ()
    priority: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid, "state": self.state, "parent_pid": self.parent_pid,
            "thread_ids": list(self.thread_ids),
            "address_space_id": self.address_space_id,
            "resource_ids": list(self.resource_ids),
            "ipc_endpoint_ids": list(self.ipc_endpoint_ids),
            "priority": self.priority,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ProcessInfo":
        def _tup(k: str) -> tuple:
            v = d.get(k, [])
            return tuple(v) if isinstance(v, list) else ()
        try:
            return ProcessInfo(
                pid=str(d.get("pid", d.get("id", "?"))),
                state=str(d.get("state", "unknown")),
                parent_pid=d.get("parent_pid"),
                thread_ids=_tup("thread_ids"),
                address_space_id=d.get("address_space_id"),
                resource_ids=_tup("resource_ids"),
                ipc_endpoint_ids=_tup("ipc_endpoint_ids"),
                priority=int(d.get("priority", 0)),
            )
        except Exception:
            return ProcessInfo(pid=str(d.get("pid", "?")))


@dataclass(frozen=True)
class ThreadInfo:
    tid: str
    owner_pid: Optional[str] = None
    state: str = "unknown"
    priority: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"tid": self.tid, "owner_pid": self.owner_pid,
                "state": self.state, "priority": self.priority}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ThreadInfo":
        try:
            return ThreadInfo(tid=str(d.get("tid", d.get("id", "?"))),
                              owner_pid=d.get("owner_pid"),
                              state=str(d.get("state", "unknown")),
                              priority=int(d.get("priority", 0)))
        except Exception:
            return ThreadInfo(tid=str(d.get("tid", "?")))


@dataclass(frozen=True)
class KernelObject:
    obj_id: str
    obj_type: str = "generic"
    owner_id: Optional[str] = None
    state: str = "unknown"
    refcount: int = 0
    references: tuple = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"obj_id": self.obj_id, "obj_type": self.obj_type,
                "owner_id": self.owner_id, "state": self.state,
                "refcount": self.refcount, "references": list(self.references)}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "KernelObject":
        try:
            refs = d.get("references", [])
            return KernelObject(
                obj_id=str(d.get("obj_id", d.get("id", "?"))),
                obj_type=str(d.get("obj_type", "generic")),
                owner_id=d.get("owner_id"), state=str(d.get("state", "unknown")),
                refcount=int(d.get("refcount", 0)),
                references=tuple(refs) if isinstance(refs, list) else ())
        except Exception:
            return KernelObject(obj_id=str(d.get("obj_id", "?")))


@dataclass(frozen=True)
class IpcEndpoint:
    ep_id: str
    owner_id: Optional[str] = None
    queue_depth: int = 0
    message_count: int = 0
    capacity: int = 0
    state: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {"ep_id": self.ep_id, "owner_id": self.owner_id,
                "queue_depth": self.queue_depth,
                "message_count": self.message_count,
                "capacity": self.capacity, "state": self.state}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "IpcEndpoint":
        try:
            qd = d.get("queue_depth")
            if qd is None:
                qd = d.get("message_count", 0)
            mc = d.get("message_count", 0)
            cap = d.get("capacity", 0)
            return IpcEndpoint(
                ep_id=str(d.get("ep_id", d.get("id", "?"))),
                owner_id=d.get("owner_id"),
                queue_depth=int(qd) if qd is not None else 0,
                message_count=int(mc) if mc is not None else 0,
                capacity=int(cap) if cap is not None else 0,
                state=str(d.get("state", "unknown")))
        except Exception:
            return IpcEndpoint(ep_id=str(d.get("ep_id", "?")))


@dataclass(frozen=True)
class ResourceRecord:
    res_id: str
    res_type: str = "generic"
    owner_id: Optional[str] = None
    state: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {"res_id": self.res_id, "res_type": self.res_type,
                "owner_id": self.owner_id, "state": self.state}

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "ResourceRecord":
        try:
            return ResourceRecord(res_id=str(d.get("res_id", d.get("id", "?"))),
                                  res_type=str(d.get("res_type", "generic")),
                                  owner_id=d.get("owner_id"),
                                  state=str(d.get("state", "unknown")))
        except Exception:
            return ResourceRecord(res_id=str(d.get("res_id", "?")))


@dataclass(frozen=True)
class OsSnapshot:
    snapshot_id: str = "snapshot-0"
    memory_regions: tuple = ()
    processes: tuple = ()
    threads: tuple = ()
    kernel_objects: tuple = ()
    ipc_endpoints: tuple = ()
    resources: tuple = ()
    metadata: Dict[str, Any] = field(default_factory=dict, compare=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "memory_regions": [r.to_dict() for r in self.memory_regions],
            "processes": [p.to_dict() for p in self.processes],
            "threads": [t.to_dict() for t in self.threads],
            "kernel_objects": [o.to_dict() for o in self.kernel_objects],
            "ipc_endpoints": [e.to_dict() for e in self.ipc_endpoints],
            "resources": [r.to_dict() for r in self.resources],
            "metadata": dict(self.metadata),
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "OsSnapshot":
        if not isinstance(d, dict):
            return OsSnapshot()
        def _list(key: str, cls: Any) -> tuple:
            items = d.get(key, [])
            if not isinstance(items, list):
                return ()
            out = []
            for it in items:
                if isinstance(it, dict):
                    try:
                        out.append(cls.from_dict(it))
                    except Exception:
                        continue
            return tuple(out)
        md = d.get("metadata", {})
        return OsSnapshot(
            snapshot_id=str(d.get("snapshot_id", "snapshot-0")),
            memory_regions=_list("memory_regions", MemoryRegion),
            processes=_list("processes", ProcessInfo),
            threads=_list("threads", ThreadInfo),
            kernel_objects=_list("kernel_objects", KernelObject),
            ipc_endpoints=_list("ipc_endpoints", IpcEndpoint),
            resources=_list("resources", ResourceRecord),
            metadata=dict(md) if isinstance(md, dict) else {},
        )


def snapshot_from_dict(d: Dict[str, Any]) -> OsSnapshot:
    """Lenient constructor: never raises on malformed input."""
    try:
        return OsSnapshot.from_dict(d)
    except Exception:
        return OsSnapshot()
