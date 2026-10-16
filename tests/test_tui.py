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
