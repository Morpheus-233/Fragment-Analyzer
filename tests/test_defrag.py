"""Unit tests for the read-only defragmentation projection."""
import copy
import json

from os5.fragment.analyzer import analyze
from os5.fragment.defrag import simulate_defrag


def demo():
    return json.loads(open("examples/snapshot.json", encoding="utf-8").read())


def mem_of(res):
    return res["statistics"]["memory"]


def test_defrag_preserves_totals_and_coalesces():
    snap = demo()
    before = mem_of(analyze(snap))
    proj = simulate_defrag(snap)
    after = mem_of(analyze(proj))
    assert after["total"] == before["total"]
    assert after["used"] == before["used"]
    assert after["free"] == before["free"]
    assert after["fragment_count"] == 1
    assert after["largest_fragment"] == before["free"]
    assert proj["metadata"]["defrag_projection"] is True
    assert proj["snapshot_id"].endswith("-defrag")


def test_defrag_does_not_mutate_input():
    snap = demo()
    frozen = copy.deepcopy(snap)
    simulate_defrag(snap)
    assert snap == frozen


def test_defrag_preserves_owners_and_order():
    snap = demo()
    proj = simulate_defrag(snap)
    alloc_before = [r["id"] for r in snap["memory_regions"] if r["state"] == "allocated"]
    alloc_after = [r["id"] for r in proj["memory_regions"] if r["state"] == "allocated"]
    assert alloc_before == alloc_after
    for r in proj["memory_regions"]:
        if r["state"] == "allocated":
            orig = next(x for x in snap["memory_regions"] if x["id"] == r["id"])
            assert r["owner_id"] == orig["owner_id"]


def test_defrag_no_free_space():
    snap = {"snapshot_id": "full",
            "memory_regions": [{"id": "a", "start": 0, "end": 100, "state": "allocated"}]}
    proj = simulate_defrag(snap)
    after = mem_of(analyze(proj))
    assert after["fragment_count"] == 0
    assert after["free"] == 0


def test_defrag_keeps_invalid_regions_flaggable():
    snap = {"snapshot_id": "bad",
            "memory_regions": [{"id": "x", "start": "a", "end": "b"},
                               {"id": "y", "start": 0, "end": 100, "state": "free"}]}
    proj = simulate_defrag(snap)
    res = analyze(proj)
    assert any(d["code"] == "FRAG001" for d in res["diagnostics"])
    assert mem_of(res)["free"] == 100
