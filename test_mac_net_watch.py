#!/usr/bin/env python3
from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

import mac_net_watch as mn


NETSTAT_SAMPLE = """
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
default            192.168.1.1        UGScIg                utun4
127                127.0.0.1          UCS                   lo0

Internet6:
default            fe80::1%en0        UGcg                  en0
""".strip()

IFCONFIG_SAMPLE = """
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tstatus: active
en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether aa:bb:cc:dd:ee:ff
\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4
\tstatus: active
""".replace("\\t", "\t")

ARP_SAMPLE = """
? (192.168.1.1) at aa:bb:cc:dd:ee:00 on en0 ifscope [ethernet]
? (192.168.1.42) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
""".strip()


def _probe(target: str, reachable: bool) -> mn.ReachabilityProbe:
    return mn.ReachabilityProbe(
        target=target,
        reachable=reachable,
        latency_ms=1.0 if reachable else None,
        outcome="connected" if reachable else "unreachable",
        detail=target,
        attempts=[],
    )


def _dns(server: str, ok: bool) -> mn.DnsProbe:
    return mn.DnsProbe(
        server=server,
        name="example.com",
        ok=ok,
        latency_ms=1.0 if ok else None,
        answer_count=1 if ok else 0,
    )


def _http(ok: bool) -> mn.HttpProbe:
    return mn.HttpProbe(
        url="https://example.com/",
        ok=ok,
        latency_ms=1.0 if ok else None,
        status_code=200 if ok else None,
    )


def _snapshot(**overrides: object) -> mn.Snapshot:
    data = dict(
        timestamp="2026-09-01T12:00:00+00:00",
        active_default=mn.RouteEntry("192.168.1.1", "en0", "UGScg"),
        local_default=mn.RouteEntry("192.168.1.1", "en0", "UGScg"),
        tunnel_defaults=[],
        interface=mn.InterfaceInfo(name="en0", status="active", ipv4=["192.168.1.42"]),
        arp_has_gateway=True,
        dns_servers=["1.1.1.1"],
        gateway_probe=_probe("192.168.1.1", True),
        public_probes=[_probe("1.1.1.1", True), _probe("8.8.8.8", True)],
        system_dns=[_dns("system", True)],
        direct_dns=[_dns("1.1.1.1", True)],
        http_probes=[_http(True)],
        regional_services=[],
        performance=mn.PerformanceView(),
        cause=mn.make_assessment("degraded", "unknown", "pending", 0.0, [], []),
    )
    data.update(overrides)
    return mn.Snapshot(**data)  # type: ignore[arg-type]


class ParseHelpersTest(unittest.TestCase):
    def test_parse_default_routes_skips_ipv6_section(self) -> None:
        routes = mn.parse_default_routes(NETSTAT_SAMPLE)
        self.assertEqual(
            [(route.gateway, route.netif) for route in routes],
            [("192.168.1.1", "en0"), ("192.168.1.1", "utun4")],
        )

    def test_parse_ifconfig_skips_loopback_ipv4(self) -> None:
        interfaces = mn.parse_ifconfig(IFCONFIG_SAMPLE)
        self.assertEqual(interfaces["en0"].status, "active")
        self.assertEqual(interfaces["en0"].ipv4, ["192.168.1.42"])
        self.assertEqual(interfaces["en0"].mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(interfaces["lo0"].ipv4, [])

    def test_parse_arp_table(self) -> None:
        self.assertEqual(mn.parse_arp_table(ARP_SAMPLE), {"192.168.1.1", "192.168.1.42"})

    def test_choose_local_default_prefers_non_tunnel(self) -> None:
        routes = mn.parse_default_routes(NETSTAT_SAMPLE)
        local = mn.choose_local_default(routes)
        self.assertIsNotNone(local)
        assert local is not None
        self.assertEqual(local.netif, "en0")
        active = mn.choose_active_default(routes)
        self.assertIsNotNone(active)
        assert active is not None
        self.assertEqual(active.netif, "en0")

    def test_dns_encode_name(self) -> None:
        self.assertEqual(mn.dns_encode_name("example.com"), b"\x07example\x03com\x00")

    def test_parse_public_endpoints_default_and_custom(self) -> None:
        self.assertEqual(mn.parse_public_endpoints(None), mn.DEFAULT_PUBLIC_ENDPOINTS)
        parsed = mn.parse_public_endpoints(["1.1.1.1:53,443", "8.8.8.8:443"])
        self.assertEqual(parsed[0], ("custom_1", "1.1.1.1", [53, 443]))
        self.assertEqual(parsed[1], ("custom_2", "8.8.8.8", [443]))

    def test_parse_public_endpoints_rejects_host_without_port(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError):
            mn.parse_public_endpoints(["1.1.1.1"])

    def test_build_speedtest_url(self) -> None:
        self.assertEqual(
            mn.build_speedtest_url("https://example.test/__down?bytes={bytes}", 100),
            "https://example.test/__down?bytes=100",
        )
        self.assertEqual(mn.build_speedtest_url("https://example.test/fixed", 100), "https://example.test/fixed")


class RatesAndLogTest(unittest.TestCase):
    def test_compute_interface_rates(self) -> None:
        previous = mn.InterfaceCounters(rx_bytes=1_000_000, tx_bytes=2_000_000, source="ifconfig")
        current = mn.InterfaceCounters(rx_bytes=2_000_000, tx_bytes=2_500_000, source="ifconfig")
        rates = mn.compute_interface_rates(previous, 10.0, current, 12.0)
        self.assertIsNotNone(rates)
        assert rates is not None
        self.assertEqual(rates.rx_mbps, 4.0)
        self.assertEqual(rates.tx_mbps, 2.0)
        self.assertEqual(rates.interval_s, 2.0)

    def test_compute_interface_rates_counter_reset(self) -> None:
        previous = mn.InterfaceCounters(rx_bytes=5_000, tx_bytes=5_000, source="ifconfig")
        current = mn.InterfaceCounters(rx_bytes=10, tx_bytes=10, source="ifconfig")
        self.assertIsNone(mn.compute_interface_rates(previous, 1.0, current, 2.0))

    def test_write_json_line_appends(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "log.jsonl"
            mn.write_json_line(path, {"event": "sample"})
            mn.write_json_line(path, {"event": "incident_opened"})
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertIn("sample", lines[0])


class AssessmentTest(unittest.TestCase):
    def test_healthy(self) -> None:
        cause = mn.build_assessment(_snapshot())
        self.assertEqual(cause.code, "healthy")
        self.assertEqual(cause.status, "ok")

    def test_gateway_unreachable(self) -> None:
        cause = mn.build_assessment(
            _snapshot(gateway_probe=_probe("192.168.1.1", False), arp_has_gateway=False)
        )
        self.assertEqual(cause.code, "gateway_unreachable")
        self.assertEqual(cause.status, "down")

    def test_local_interface_down(self) -> None:
        cause = mn.build_assessment(_snapshot(interface=mn.InterfaceInfo(name="en0", status="inactive", ipv4=[])))
        self.assertEqual(cause.code, "local_interface_down")

    def test_local_dns_failure(self) -> None:
        cause = mn.build_assessment(
            _snapshot(system_dns=[_dns("system", False)], direct_dns=[_dns("1.1.1.1", True)])
        )
        self.assertEqual(cause.code, "local_dns_failure")
        self.assertEqual(cause.status, "degraded")

    def test_upstream_wan_failure(self) -> None:
        cause = mn.build_assessment(
            _snapshot(public_probes=[_probe("1.1.1.1", False), _probe("8.8.8.8", False)])
        )
        self.assertEqual(cause.code, "upstream_wan_failure")

    def test_http_layer_failure(self) -> None:
        cause = mn.build_assessment(_snapshot(http_probes=[_http(False)]))
        self.assertEqual(cause.code, "http_layer_failure")


if __name__ == "__main__":
    unittest.main()
