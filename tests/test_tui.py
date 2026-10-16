import copy
import json

from textual.widgets import Checkbox, DataTable, Input, TabbedContent

from netwatch import core
from netwatch.engine import Monitor
from netwatch.settings import Settings
from netwatch.storage import Journal
from netwatch.tui import Help, NetWatchApp
from test_mac_net_watch import _snapshot


async def wait_for_samples(pilot, monitor, count):
    for _ in range(40):
        if monitor.total >= count:
            return
        await pilot.pause(.05)
    raise AssertionError(f"Expected {count} samples, got {monitor.total}")


async def test_dashboard_navigation_pause_filter_report_and_help(tmp_path, monkeypatch):
    monitor = Monitor(Settings(interval=3600), Journal(tmp_path))
    sample = _snapshot(cause=core.build_assessment(_snapshot()), platform="TestOS")
    monkeypatch.setattr(monitor, "sample", lambda: copy.deepcopy(sample))
    app = NetWatchApp(monitor)
    async with app.run_test(size=(140, 45)) as pilot:
        await wait_for_samples(pilot, monitor, 1)
        assert app.latest.platform == "TestOS"
        assert app.ui("#chain", DataTable).row_count == 7
        await pilot.press("p")
        assert app.paused
        await pilot.press("r")
        await wait_for_samples(pilot, monitor, 2)
        assert app.paused  # A manual sample does not restart automatic polling.
        await pilot.press("2")
        assert app.ui("#tabs", TabbedContent).active == "probes"
        app.ui("#errors-only", Checkbox).value = True
        await pilot.pause()
        assert app.ui("#probe-table", DataTable).row_count == 0
        app.ui("#errors-only", Checkbox).value = False
        app.ui("#filter", Input).value = "example.com"
        await pilot.pause()
        assert app.ui("#probe-table", DataTable).row_count > 0
        await pilot.press("e")
        assert len(list((tmp_path / "reports").glob("*.json"))) == 1
        await pilot.press("?")
        await pilot.pause(.4)  # Session timer must keep working underneath a modal.
        assert isinstance(app.screen, Help)
        await pilot.press("escape")
        await pilot.press("5")
        assert app.ui("#tabs", TabbedContent).active == "settings"
        app.ui("#interval-input", Input).value = "10"
        app.apply_settings()
        assert monitor.settings.interval == 10
        app.save_settings()
        saved = list(tmp_path.glob("profile-*.json"))
        assert json.loads(saved[0].read_text())["interval"] == 10


async def test_narrow_terminal_and_resize(tmp_path, monkeypatch):
    monitor = Monitor(Settings(interval=3600), Journal(tmp_path, enabled=False))
    sample = _snapshot(cause=core.build_assessment(_snapshot()), platform="TestOS")
    monkeypatch.setattr(monitor, "sample", lambda: copy.deepcopy(sample))
    app = NetWatchApp(monitor)
    async with app.run_test(size=(80, 24)) as pilot:
        await wait_for_samples(pilot, monitor, 1)
        assert app.has_class("compact")
        await pilot.resize_terminal(140, 45)
        await pilot.pause()
        assert not app.has_class("compact")
        await pilot.press("4")
        assert app.ui("#tabs", TabbedContent).active == "events"


async def test_download_action_and_error_recovery(tmp_path, monkeypatch, http_server):
    url, _ = http_server
    monitor = Monitor(Settings(interval=3600, speedtest_url=url, speedtest_bytes=2048), Journal(tmp_path, enabled=False))
    sample = _snapshot(cause=core.build_assessment(_snapshot()))
    def fail():
        raise OSError("test-unavailable")
    monkeypatch.setattr(monitor, "sample", fail)
    app = NetWatchApp(monitor)
    async with app.run_test(size=(120, 40)) as pilot:
        for _ in range(30):
            if app.last_error:
                break
            await pilot.pause(.05)
        assert "test-unavailable" in app.last_error
        monkeypatch.setattr(monitor, "sample", lambda: copy.deepcopy(sample))
        await pilot.press("r")
        await wait_for_samples(pilot, monitor, 1)
        assert app.last_error is None
        await pilot.press("s")
        for _ in range(30):
            if monitor.speed_result:
                break
            await pilot.pause(.05)
        assert monitor.speed_result.ok
        assert monitor.speed_result.transferred_bytes == 2048
        assert not app.speed_running


async def test_v4_editor_diagnostics_history_and_comparison(tmp_path, monkeypatch):
    from textual.widgets import Button, Select
    from textual.widgets._button import Button as ButtonType
    from netwatch import tools
    monitor = Monitor(Settings(interval=3600), Journal(tmp_path))
    sample = _snapshot(timestamp=core.iso_now(), cause=core.build_assessment(_snapshot()), platform='TestOS')
    monkeypatch.setattr(monitor, 'sample', lambda: copy.deepcopy(sample))
    monkeypatch.setattr(tools, 'run', lambda m, tool, target: m.record_diagnostic(tool, {'status': 'ok', 'source': 'fixture'}))
    app = NetWatchApp(monitor)
    async with app.run_test(size=(150, 50)) as pilot:
        await wait_for_samples(pilot, monitor, 1)
        app.paused = True
        await pilot.press('5')
        app.ui('#target-kind', Select).value = 'http_urls'
        app.ui('#target-input', Input).value = 'https://test.example/check'
        app.edit_target(Button.Pressed(app.ui('#target-add', Button)))
        assert 'https://test.example/check' in monitor.settings.http_urls
        app.ui('#assert-code', Input).value = '204'
        app.apply_assertion()
        assert monitor.settings.http_assertions['https://test.example/check']['status'] == 204
        app.ui('#target-input', Input).value = 'file:///invalid'
        app.edit_target(Button.Pressed(app.ui('#target-add', Button)))
        assert 'file:///invalid' not in monitor.settings.http_urls
        app.ui('#task-profile', Select).value = 'economy'
        app.apply_preset()
        assert monitor.settings.interval == 30
        assert monitor.settings.regional_services == []
        await pilot.press('6')
        app.refresh_archive()
        for _ in range(30):
            if app.ui('#history-table', DataTable).row_count:
                break
            await pilot.pause(.05)
        assert app.ui('#history-table', DataTable).row_count == 1
        await pilot.press('7')
        app.tool_clicked()
        for _ in range(30):
            if not app.tool_running:
                break
            await pilot.pause(.05)
        assert monitor.diagnostics[-1]['tool'] == 'wifi'
        await pilot.press('8')
        app.capture_before()
        app.compare_after()
        await wait_for_samples(pilot, monitor, 2)
        assert monitor.diagnostics[-1]['tool'] == 'comparison'
        assert monitor.diagnostics[-1]['result']['same_targets']


async def test_offline_tui_has_no_live_measurements_and_opens_history(tmp_path, monkeypatch):
    from dataclasses import asdict
    monitor = Monitor(Settings(), Journal(tmp_path, False))
    snapshot = _snapshot(timestamp=core.iso_now(), cause=core.build_assessment(_snapshot()))
    monitor.load_offline({'snapshots': [asdict(snapshot)], 'incidents': [], 'diagnostics': []})
    def forbidden(*args, **kwargs):
        raise AssertionError('Network operation in offline viewer')
    monkeypatch.setattr(monitor, 'sample', forbidden)
    monkeypatch.setattr(monitor, 'measure_speed', forbidden)
    app = NetWatchApp(monitor)
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause(.3)
        assert app.paused
        assert app.latest.timestamp == snapshot.timestamp
        await pilot.press('r', 'p', 's', '6')
        await pilot.pause(.3)
        assert app.ui('#history-table', DataTable).row_count == 1
        assert monitor.total == 1
    assert not tmp_path.joinpath('history.sqlite3').exists()


async def test_continuous_mtr_updates_and_stops(tmp_path, monkeypatch):
    from textual.widgets import Select
    from netwatch import tools
    monitor = Monitor(Settings(interval=3600), Journal(tmp_path, False))
    sample = _snapshot(timestamp=core.iso_now(), cause=core.build_assessment(_snapshot()))
    monkeypatch.setattr(monitor, 'sample', lambda: copy.deepcopy(sample))
    calls = []
    def trace(m, tool, target):
        calls.append(target)
        return m.record_diagnostic('trace', {'target': target, 'method': 'fixture', 'hops': [
            {'hop': 1, 'addresses': ['127.0.0.1'], 'latencies_ms': [1., 2.], 'responded': 2, 'attempts': 2}]})
    monkeypatch.setattr(tools, 'run', trace)
    app = NetWatchApp(monitor)
    async with app.run_test(size=(140, 45)) as pilot:
        await wait_for_samples(pilot, monitor, 1)
        app.paused = True
        app.action_tab('tools-tab')
        app.ui('#tool-select', Select).value = 'trace'
        app.ui('#tool-target', Input).value = '127.0.0.1'
        app.ui('#trace-repeat', Checkbox).value = True
        app.tool_clicked()
        for _ in range(100):
            if len(calls) >= 2:
                break
            await pilot.pause(.05)
        assert len(calls) >= 2
        assert app.ui('#trace-table', DataTable).row_count == 1
        app.stop_tool()
        for _ in range(30):
            if not app.tool_running:
                break
            await pilot.pause(.05)
        assert not app.tool_running
        assert monitor.diagnostics[-1]['result']['rounds'] >= 2
        stopped = len(calls)
        await pilot.pause(.3)
        assert len(calls) == stopped
