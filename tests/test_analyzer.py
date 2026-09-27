"""Synthetic OS5-state tests (project-local fixtures only; never host state)."""
import json
from pathlib import Path

from os5.fragment.analyzer import AnalyzerConfig, FragmentAnalyzer, analyze
from os5.fragment.memory import analyze_memory
from os5.fragment.process import analyze_processes
from os5.fragment.ipc import analyze_ipc
from os5.fragment.kobjects import analyze_objects
from os5.fragment.resources import analyze_resources
from os5.fragment.snapshot import snapshot_from_dict, OsSnapshot
from os5.fragment.report import to_text, to_json
from os5.fragment.cli import _is_forbidden, main


def valid_snapshot():
    return {
        "snapshot_id": "s-valid",
        "memory_regions": [
            {"id": "r0", "start": 0, "end": 100, "state": "allocated", "owner_id": "p1"},
            {"id": "r1", "start": 100, "end": 200, "state": "free"},
            {"id": "r2", "start": 200, "end": 300, "state": "allocated", "owner_id": "p1"},
            {"id": "r3", "start": 300, "end": 400, "state": "free"},
            {"id": "r4", "start": 400, "end": 500, "state": "allocated", "owner_id": "p1"},
            {"id": "r5", "start": 500, "end": 600, "state": "free"},
        ],
        "processes": [{"pid": "p1", "state": "running", "thread_ids": ["t1"]}],
        "threads": [{"tid": "t1", "owner_pid": "p1", "state": "running"}],
        "kernel_objects": [{"obj_id": "o1", "obj_type": "mutex", "owner_id": "p1", "refcount": 0}],
        "ipc_endpoints": [{"ep_id": "e1", "owner_id": "p1", "queue_depth": 2, "message_count": 2, "capacity": 8}],
        "resources": [{"res_id": "f1", "res_type": "file", "owner_id": "p1"}],
    }


def test_memory_fragmentation_metrics():
    out = analyze_memory(valid_snapshot())
    assert out["free_fragments"] == 3
    assert out["free"] == 300
    assert out["used"] == 300
    assert out["total"] == 600
    assert out["largest_free"] == 100


def test_full_analysis_valid():
    res = analyze(valid_snapshot())
    assert res["snapshot_id"] == "s-valid"
    assert res["consistent"] is True
    assert res["statistics"]["memory"]["fragment_count"] == 3
    assert res["statistics"]["processes"]["process_count"] == 1


def test_owner_mismatch_diagnostic():
    snap = valid_snapshot()
    snap["memory_regions"][0]["owner_id"] = "p-nope"
    res = analyze(snap)
    codes = [d["code"] for d in res["diagnostics"]]
    assert "FRAG002" in codes


def test_overlap_diagnostic():
    snap = {"snapshot_id": "s-over", "memory_regions": [
        {"id": "a", "start": 4096, "end": 12288, "state": "allocated"},
        {"id": "b", "start": 8192, "end": 16384, "state": "free"}]}
    res = analyze(snap)
    codes = [d["code"] for d in res["diagnostics"]]
    assert "FRAG003" in codes
    assert res["consistent"] is False


def test_multiple_nonadjacent_overlaps():
    snap = {
        "snapshot_id": "s-multi-over",
        "memory_regions": [
            {"id": "r-wide", "start": 0, "end": 1000, "state": "allocated"},
            {"id": "r-inner1", "start": 100, "end": 200, "state": "allocated"},
            {"id": "r-inner2", "start": 300, "end": 400, "state": "allocated"},
        ]
    }
    out = analyze_memory(snap)
    overlaps = [d for d in out["diagnostics"] if d["code"] == "FRAG003"]
    assert len(overlaps) == 2


def test_duplicate_thread_diagnostic():
    snap = {
        "processes": [{"pid": "p1", "state": "running"}],
        "threads": [
            {"tid": "t1", "owner_pid": "p1"},
            {"tid": "t1", "owner_pid": "p1"},
        ]
    }
    out = analyze_processes(snap)
    dup = [d for d in out["diagnostics"] if d["code"] == "FRAG009"]
    assert len(dup) == 1
    assert "duplicate thread id t1" in dup[0]["message"]


def test_ipc_negative_queue_diagnostic():
    snap = {
        "ipc_endpoints": [
            {"ep_id": "e-bad", "queue_depth": -1, "message_count": -5, "capacity": -10}
        ]
    }
    out = analyze_ipc(snap)
    diags = [d for d in out["diagnostics"] if d["code"] == "FRAG007"]
    assert any("negative queue field" in d["message"] for d in diags)


def test_kobject_non_numeric_refcount():
    snap = {
        "kernel_objects": [
            {"obj_id": "o-bad", "refcount": "not-a-number"}
        ]
    }
    out = analyze_objects(snap)
    diags = [d for d in out["diagnostics"] if d["code"] == "FRAG005"]
    assert any("non-numeric refcount" in d["message"] for d in diags)


def test_malformed_never_crashes():
    for bad in ({}, {"memory_regions": "nope"}, {"memory_regions": [{"id": "x"}]},
                {"snapshot_id": 1, "processes": [{"no": 1}]}, {"memory_regions": None}):
        res = analyze(bad)
        assert "diagnostics" in res and "statistics" in res


def test_empty_snapshot():
    res = analyze({"snapshot_id": "empty"})
    assert res["consistent"] is True
    assert res["diagnostics"] == []


def test_determinism():
    a = json.dumps(analyze(valid_snapshot()), sort_keys=True)
    b = json.dumps(analyze(valid_snapshot()), sort_keys=True)
    assert a == b


def test_cli_rejects_host_scopes():
    assert _is_forbidden("/") and _is_forbidden("/proc") and _is_forbidden("/dev")
    assert _is_forbidden("C:\\Windows") and _is_forbidden("c:/windows/system32")


def test_cli_module_filtering(capsys):
    ret = main(["analyze", "examples/snapshot.json", "--memory", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["metadata"]["modules"] == ["memory"]

    ret = main(["analyze", "examples/snapshot.json", "--resources", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["metadata"]["modules"] == ["resources"]


def test_cli_strict_mode():
    ret_ok = main(["analyze", "examples/snapshot.json", "--strict"])
    assert ret_ok == 0

    ret_fail = main(["analyze", "examples/corrupted_system.json", "--strict"])
    assert ret_fail == 1


def test_cli_diagnostics_flag(capsys):
    ret = main(["analyze", "examples/corrupted_system.json", "--diagnostics"])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "diagnostics" in data and len(data["diagnostics"]) > 0
    assert "fragments" not in data


def test_cli_output_to_file(tmp_path):
    out_file = tmp_path / "test_out.json"
    ret = main(["analyze", "examples/snapshot.json", "--json", "--output", str(out_file)])
    assert ret == 0
    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["snapshot_id"] == "demo-1"


def test_report_formatting():
    res = analyze(valid_snapshot())
    text_out = to_text(res)
    assert "OS5 Fragment Analysis: s-valid" in text_out
    assert "Status: CONSISTENT [OK]" in text_out
    json_out = to_json(res)
    assert json.loads(json_out)["snapshot_id"] == "s-valid"


def test_snapshot_roundtrip():
    data = valid_snapshot()
    snap = snapshot_from_dict(data)
    assert isinstance(snap, OsSnapshot)
    assert snap.snapshot_id == "s-valid"
    d = snap.to_dict()
    assert d["snapshot_id"] == "s-valid"
    assert len(d["memory_regions"]) == 6


def test_all_example_outputs_match():
    examples_dir = Path("examples")
    outputs_dir = examples_dir / "outputs"
    for ex_file in sorted(examples_dir.glob("*.json")):
        out_file = outputs_dir / f"{ex_file.stem}_output.json"
        if not out_file.exists():
            continue
        snap_data = json.loads(ex_file.read_text(encoding="utf-8"))
        exp_data = json.loads(out_file.read_text(encoding="utf-8"))
        actual = analyze(snap_data)
        assert actual["consistent"] == exp_data["consistent"], f"Consistency mismatch for {ex_file.name}"
        assert len(actual["diagnostics"]) == len(exp_data["diagnostics"]), f"Diagnostic count mismatch for {ex_file.name}"
