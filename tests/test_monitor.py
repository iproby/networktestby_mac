import copy
import json
import struct
import subprocess
import sys
from dataclasses import replace

import pytest

from netwatch import core, engine
from netwatch.cli import main
from netwatch.engine import Monitor
from netwatch.native import NativeState
from netwatch.settings import Settings
from netwatch.storage import Journal
from test_mac_net_watch import _http, _probe, _snapshot


def test_filtered_router_does_not_imply_router_failure():
    s = _snapshot(gateway_probe=_probe("192.168.1.1", False))
    assert core.build_assessment(s).code == "healthy"


def test_proxy_path_does_not_imply_wan_outage():
    s = _snapshot(public_probes=[_probe("1.1.1.1", False)], proxy_detected=True)
    assert core.build_assessment(s).code == "proxy_path"


def test_http_success_with_failed_tcp_is_not_healthy():
    s = _snapshot(public_probes=[_probe("1.1.1.1", False)])
    assert core.build_assessment(s).code == "direct_tcp_unavailable"


def test_ipv6_address_does_not_imply_interface_down():
    s = _snapshot(interface=core.InterfaceInfo("en0", "active", ipv6=["2001:db8::1"]))
    assert core.build_assessment(s).code == "healthy"


def test_collection_failure_is_not_dhcp_failure():
    s = _snapshot(active_default=None, local_default=None, collection_warnings=["permission denied"])
    assert core.build_assessment(s).code == "collection_limited"


def test_region_failure_is_visible():
    p = core.RegionalServiceProbe("X", "Test", "Test", "https://example.com", False, None, 403, "HTTP 403")
    assert core.build_assessment(_snapshot(regional_services=[p])).code == "service_partial"


def test_actual_tcp_http_dns_and_counters(http_server, monkeypatch, tmp_path):
    url, port = http_server
    values = iter([1000, 2000])
    def native():
        return NativeState("TestOS", interfaces={"eth0": core.InterfaceInfo("eth0", "active", ["192.168.1.2"])},
                           routes=[core.RouteEntry("0.0.0.0", "eth0", "U")],
                           counters={"eth0": core.InterfaceCounters(next(values), 500, "fixture")})
    monkeypatch.setattr(engine, "collect_native", native)
    monitor = Monitor(Settings(public_endpoints=[f"127.0.0.1:{port}"], http_urls=[url], dns_names=["localhost"],
                               dns_servers=[], regional_services=[]), Journal(tmp_path))
    first = monitor.sample()
    monitor.accept(first)
    second = monitor.sample()
    monitor.accept(second)
    assert first.performance.interface_rates is None
    assert second.performance.interface_rates.rx_mbps > 0
    assert first.public_probes[0].reachable
    assert first.http_probes[0].ok
    assert first.system_dns[0].ok
    assert monitor.total == 2
    report = json.loads(monitor.export().read_text(encoding="utf-8"))
    assert len(report["snapshots"]) == 2
    assert report["total_samples"] == 2
    assert "application" in report


def test_http_403_preserves_error(http_server):
    url, _ = http_server
    result = core.http_probe(url + "/blocked", 1)
    assert not result.ok
    assert result.status_code == 403


def test_speedtest_respects_byte_budget(http_server):
    url, _ = http_server
    result = core.measure_download_speed(url, 2, max_bytes=2048)
    assert result.ok
    assert result.transferred_bytes == 2048
    assert result.download_mbps > 0
    assert result.provider == "127.0.0.1"


@pytest.mark.parametrize("response_flags,correct_id,ok", [(0x8180, True, True), (0x0100, True, False),
                                                           (0x8380, True, False), (0x8180, False, False)])
def test_dns_validates_response(monkeypatch, response_flags, correct_id, ok):
    class Socket:
        def setblocking(self, value): pass
        def connect(self, destination): pass
        def send(self, packet): self.query_id = struct.unpack("!H", packet[:2])[0]
        def recv(self, size):
            query_id = self.query_id if correct_id else (self.query_id + 1) % 65536
            return struct.pack("!HHHHHH", query_id, response_flags, 1, 1, 0, 0)
        def close(self): pass
    monkeypatch.setattr(core.socket, "socket", lambda *_: Socket())
    monkeypatch.setattr(core.select, "select", lambda read, *_: (read, [], []))
    assert core.dns_query("1.1.1.1", "example.com", 1).ok is ok


def test_incident_lifecycle_and_bounded_history(tmp_path):
    monitor = Monitor(Settings(), Journal(tmp_path))
    down = _snapshot(timestamp="2026-01-01T12:00:00+00:00")
    down.cause = core.make_assessment("down", "upstream_wan_failure", "WAN unavailable", .8, [], [])
    monitor.accept(down)
    monitor.accept(replace(down, timestamp="2026-01-01T12:00:05+00:00"))
    monitor.accept(_snapshot(timestamp="2026-01-01T12:00:10+00:00", cause=core.build_assessment(_snapshot())))
    assert monitor.active_incident is None
    assert len(monitor.incidents) == 1
    assert monitor.incidents[0]["samples"] == 2
    assert monitor.incidents[0]["ended_at"] == "2026-01-01T12:00:10+00:00"
    assert monitor.healthy == 1


def test_log_rotation(tmp_path):
    journal = Journal(tmp_path)
    journal.max_bytes = 1
    for index in range(10):
        journal.append({"event": "sample", "index": index})
    assert len(list(tmp_path.glob("network-diagnostics.jsonl*"))) == 4
    assert json.loads(journal.path.read_text())["index"] == 9


def test_storage_failure_is_visible(monkeypatch, tmp_path):
    journal = Journal(tmp_path)
    def fail(event):
        raise PermissionError("test-denied")
    monkeypatch.setattr(journal, "append", fail)
    monitor = Monitor(Settings(), journal)
    monitor.accept(_snapshot())
    assert "test-denied" in monitor.storage_warning
    assert monitor.total == 1


def test_custom_log_location_and_rotation(tmp_path):
    journal = Journal(tmp_path / "state")
    journal.path = tmp_path / "custom" / "trace.log"
    journal.max_bytes = 1
    journal.append({"event": "first"})
    journal.append({"event": "second"})
    assert json.loads(journal.path.read_text())["event"] == "second"
    assert journal.path.with_name("trace.log.1").exists()
    assert journal.directory == tmp_path / "state"


def test_json_cli_is_one_valid_document_per_line(http_server, tmp_path):
    url, port = http_server
    result = subprocess.run([sys.executable, "-m", "netwatch", "--once", "--json", "--timeout", ".1",
                             "--dns-name", "localhost", "--no-direct-dns", "--no-regions", "--http-url", url,
                             "--public-endpoint", f"127.0.0.1:{port}", "--state-dir", str(tmp_path),
                             "--speedtest", "--speedtest-url", url, "--speedtest-bytes", "1024"],
                            text=True, encoding="utf-8", capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert len(result.stdout.splitlines()) == 1
    snapshot = json.loads(result.stdout)
    assert snapshot["http_probes"][0]["ok"]
    assert snapshot["public_probes"][0]["reachable"]
    assert snapshot["performance"]["cloudflare_speed"]["transferred_bytes"] == 1024
    assert list(tmp_path.glob("*.jsonl"))


def test_invalid_configuration_exits_cleanly(capsys):
    assert main(["--interval", "nan", "--once"]) == 2
    assert "interval" in capsys.readouterr().err
