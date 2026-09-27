"""Dashboard regression tests (headless AppTest) + analyzer fuzz (never crash).

All fixtures are synthetic and project-local; the dashboard is never
pointed at host state.
"""
import random

from streamlit.testing.v1 import AppTest

from os5.fragment.analyzer import analyze

APP = "../dashboard/app.py"

EVIL_SNAPSHOT = (
    '{"snapshot_id":"evil","memory_regions":['
    '{"id":"x","start":"a","end":"b"},'
    '{"id":"y","start":10,"end":5},'
    '{"id":"z","start":null,"end":null}],'
    '"ipc_endpoints":[{"ep_id":"e","message_count":"NaN","capacity":"x"}],'
    '"kernel_objects":[{"obj_id":"o","refcount":"zzz","references":[1,2]}],'
    '"processes":"not-a-list","threads":[null,42]}'
)


def _example_picker(app):
    for sb in app.selectbox:
        if sb.key is None:
            return sb
    raise AssertionError("sidebar snapshot picker not found")


def _apply_button(app):
    for b in app.button:
        if "Apply" in str(b.label):
            return b
    raise AssertionError("apply button not found")


def test_dashboard_demo_renders_without_error():
    app = AppTest.from_file(APP)
    app.run()
    assert not app.error
    assert len(app.tabs) == 9
    assert len(app.metric) >= 6


def test_dashboard_evil_snapshot_never_crashes():
    app = AppTest.from_file(APP)
    app.run()
    assert not app.error
    app.radio[0].set_value("Live Sandbox").run()
    app.text_area[0].set_value(EVIL_SNAPSHOT)
    _apply_button(app).click().run()
    assert not app.error


def test_dashboard_corrupted_example_without_error():
    app = AppTest.from_file(APP)
    app.run()
    _example_picker(app).set_value("corrupted_system.json").run()
    assert not app.error


def test_dashboard_severity_filter_changes_metrics():
    app = AppTest.from_file(APP)
    app.run()
    _example_picker(app).set_value("corrupted_system.json").run()
    assert not app.error
    app.segmented_control[0].set_value("error").run()
    assert not app.error
    metrics_err = [m.label for m in app.metric]
    assert "Warnings" not in metrics_err
    assert "Errors" in metrics_err


def test_dashboard_disabled_module_shows_notice():
    app = AppTest.from_file(APP)
    app.run()
    app.pills[0].set_value(["memory", "processes"]).run()
    assert not app.error
    notices = " ".join(str(x.value) for x in app.info)
    assert "Objects analyzer module is disabled" in notices
    assert "IPC analyzer module is disabled" in notices
    assert "Resources analyzer module is disabled" in notices


def test_dashboard_defrag_projection_renders():
    app = AppTest.from_file(APP)
    app.run()
    app.checkbox[0].set_value(True).run()
    assert not app.error
    tables = [" ".join(map(str, t.value.columns)) for t in app.table]
    assert any("Projected" in cols for cols in tables)


def test_dashboard_no_modules_without_error():
    app = AppTest.from_file(APP)
    app.run()
    app.pills[0].set_value([]).run()
    assert not app.error


def test_analyzer_fuzz_never_crashes():
    rng = random.Random(20260927)
    pools = [None, True, 42, "s", [], {}, [None], {"id": "q"}]
    for _ in range(300):
        snap = {
            "snapshot_id": rng.choice([None, 1, "fuzz"]),
            "memory_regions": [rng.choice(pools) for _ in range(rng.randint(0, 4))],
            "processes": [rng.choice(pools) for _ in range(rng.randint(0, 3))],
            "threads": [rng.choice(pools) for _ in range(rng.randint(0, 3))],
            "kernel_objects": [rng.choice(pools) for _ in range(rng.randint(0, 3))],
            "ipc_endpoints": [rng.choice(pools) for _ in range(rng.randint(0, 3))],
            "resources": [rng.choice(pools) for _ in range(rng.randint(0, 3))],
        }
        if rng.random() < 0.3:
            snap["memory_regions"].append(
                {"id": "r", "start": rng.choice([-5, "a", None, 100]),
                 "end": rng.choice([-1, "b", None, 50])})
        res = analyze(snap)
        assert "diagnostics" in res and "statistics" in res
