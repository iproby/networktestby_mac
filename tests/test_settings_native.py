import argparse
import json

import pytest

from netwatch import native
from netwatch.core import parse_public_endpoints
from netwatch.settings import Settings


@pytest.mark.parametrize("value", [-1, 0, float("nan"), float("inf"), True, "5"])
def test_invalid_intervals(value):
    with pytest.raises(ValueError):
        Settings(interval=value).validate()


@pytest.mark.parametrize("url", ["file:///etc/passwd", "https://user:pass@example.com", "example.com", "ftp://example.com"])
def test_invalid_urls(url):
    with pytest.raises(ValueError):
        Settings(http_urls=[url]).validate()


def test_profiles_roundtrip_and_preserve_existing_file(tmp_path):
    path = tmp_path / "profile.json"
    Settings(interval=10, regional_services=[]).save(path)
    assert Settings.load(path).interval == 10
    with pytest.raises(FileExistsError):
        Settings().save(path)
    path.write_text('{"typo": true}', encoding="utf-8")
    with pytest.raises(ValueError, match="typo"):
        Settings.load(path)


@pytest.mark.parametrize("target", ["host:443", "1.1.1.1:0", "1.1.1.1:70000", "1.1.1.1:", "1.1.1.1:x"])
def test_endpoint_validation(target):
    with pytest.raises(argparse.ArgumentTypeError):
        parse_public_endpoints([target])


def test_ipv6_endpoint():
    assert parse_public_endpoints(["[2606:4700::1111]:443"])[0][1:] == ("2606:4700::1111", [443])


def test_linux_metric_order_and_reject_routes():
    text = """Iface Destination Gateway Flags RefCnt Use Metric Mask
eth0 00000000 0101A8C0 0003 0 0 200 00000000
wg0 00000000 00000000 0001 0 0 10 00000000
dead 00000000 00000000 0201 0 0 0 00000000
"""
    routes = native.linux_routes(text)
    assert [r.netif for r in routes] == ["wg0", "eth0"]
    assert routes[1].gateway == "192.168.1.1"


def test_linux_ipv6_only_default():
    text = "0" * 32 + " 00 " + "0" * 32 + " 00 fe800000000000000000000000000001 00000064 00000000 00000000 00000003 eth0"
    route = native.linux_routes("Iface Destination Gateway Flags RefCnt Use Metric Mask", text)[0]
    assert route.gateway == "fe80::1%eth0"


def test_windows_metric_alias_and_tunnel():
    routes, dns = native.windows_state(json.dumps({"routes": [
        {"DestinationPrefix": "0.0.0.0/0", "InterfaceAlias": "Wi-Fi", "NextHop": "192.168.1.1", "RouteMetric": 1, "InterfaceMetric": 100},
        {"DestinationPrefix": "0.0.0.0/0", "InterfaceAlias": "Work", "NextHop": "10.0.0.1", "RouteMetric": 5,
         "InterfaceMetric": 5, "Description": "WireGuard Tunnel"}], "dns": "1.1.1.1"}))
    assert routes[0].netif == "Work"
    assert routes[0].flags == "T"
    assert dns == ["1.1.1.1"]


def test_windows_single_route_and_ipv6_scope():
    routes, _ = native.windows_state(json.dumps({"routes": {
        "DestinationPrefix": "::/0", "InterfaceAlias": "Wi-Fi", "NextHop": "fe80::1", "InterfaceIndex": 8}}))
    assert routes[0].gateway == "fe80::1%8"


def test_macos_active_route_and_dns_deduplication(monkeypatch):
    monkeypatch.setattr(native.platform, "system", lambda: "Darwin")
    def command(args, **kwargs):
        if args[0] == "netstat":
            return 0, "Internet:\nDestination Gateway Flags Netif\ndefault 192.168.1.1 UG en0\ndefault 10.0.0.1 UG utun4", ""
        if args[0] == "route":
            return 0, "gateway: 10.0.0.1\ninterface: utun4", ""
        return 0, "nameserver[0] : 1.1.1.1\nnameserver[1] : 1.1.1.1", ""
    monkeypatch.setattr(native, "run_command", command)
    result = native.collect_native()
    assert result.routes[0].netif == "utun4"
    assert result.routes[1].netif == "en0"
    assert result.dns_servers == ["1.1.1.1"]


def test_unsupported_system_is_reported(monkeypatch):
    monkeypatch.setattr(native.platform, "system", lambda: "OtherOS")
    assert native.collect_native().warnings
