#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import json
import random
import re
import select
import socket
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_PUBLIC_ENDPOINTS = [
    ("cloudflare_dns", "1.1.1.1", [53, 443]),
    ("google_dns", "8.8.8.8", [53, 443]),
    ("quad9_dns", "9.9.9.9", [53, 443]),
]
DEFAULT_HTTP_URLS = [
    "https://cp.cloudflare.com/generate_204",
    "https://www.apple.com/library/test/success.html",
]
DEFAULT_REGIONAL_SERVICES = [
    ("BY", "Беларусь", "NBRB", "https://www.nbrb.by/"),
    ("BY2", "Беларусь", "MVD", "https://mvd.gov.by/"),
    ("RU", "Россия", "Yandex", "https://yandex.ru/"),
    ("EU", "Европа", "Europa", "https://europa.eu/"),
    ("US", "США", "Google", "https://www.google.com/"),
    ("SA", "Южная Америка", "Gov.br", "https://www.gov.br/"),
    ("JP", "Япония", "Yahoo Japan", "https://www.yahoo.co.jp/"),
    ("AU", "Австралия", "ABC", "https://www.abc.net.au/"),
    ("MY", "Малайзия", "Malaysia Gov", "https://www.malaysia.gov.my/"),
    ("CN", "Китай", "Baidu", "https://www.baidu.com/"),
]
DEFAULT_DNS_NAMES = [
    "example.com",
    "cloudflare.com",
]
RECOVERABLE_CONNECT_ERRORS = {0, errno.ECONNREFUSED, 10061}
LIKELY_UNREACHABLE_ERRORS = {getattr(errno, name) for name in
    ("ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH", "EHOSTDOWN", "ENETDOWN", "EADDRNOTAVAIL")
    if hasattr(errno, name)} | {10060, 10065, 10051, 10064, 10050, 10049}
DEFAULT_CLOUDFLARE_SPEED_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="milliseconds")


def monotonic_ms() -> float:
    return time.monotonic() * 1000


@dataclass
class RouteEntry:
    gateway: str
    netif: str
    flags: str


@dataclass
class InterfaceInfo:
    name: str
    status: str = "unknown"
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    mac: str | None = None


@dataclass
class PortProbe:
    port: int
    reachable: bool
    latency_ms: float | None
    outcome: str
    error_code: int | None = None
    detail: str | None = None


@dataclass
class ReachabilityProbe:
    target: str
    reachable: bool
    latency_ms: float | None
    outcome: str
    detail: str
    attempts: list[PortProbe]


@dataclass
class DnsProbe:
    server: str
    name: str
    ok: bool
    latency_ms: float | None
    answer_count: int = 0
    rcode: int | None = None
    error: str | None = None


@dataclass
class HttpProbe:
    url: str
    ok: bool
    latency_ms: float | None
    status_code: int | None = None
    error: str | None = None


@dataclass
class RegionalServiceProbe:
    code: str
    region: str
    name: str
    url: str
    ok: bool
    latency_ms: float | None
    status_code: int | None = None
    error: str | None = None


@dataclass
class InterfaceCounters:
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    source: str | None = None


@dataclass
class InterfaceRates:
    rx_mbps: float | None = None
    tx_mbps: float | None = None
    interval_s: float | None = None
    source: str | None = None


@dataclass
class SpeedTestProbe:
    provider: str
    label: str
    url: str
    ok: bool
    download_mbps: float | None
    transferred_bytes: int
    duration_s: float | None
    ttfb_ms: float | None
    measured_at: str
    error: str | None = None


@dataclass
class PerformanceView:
    interface_counters: InterfaceCounters | None = None
    interface_rates: InterfaceRates | None = None
    cloudflare_speed: SpeedTestProbe | None = None
    speedtest_running: bool = False


@dataclass
class CauseAssessment:
    status: str
    code: str
    summary: str
    confidence: float
    culprit: str
    evidence: list[str]
    next_steps: list[str]


@dataclass
class Snapshot:
    timestamp: str
    active_default: RouteEntry | None
    local_default: RouteEntry | None
    tunnel_defaults: list[RouteEntry]
    interface: InterfaceInfo | None
    arp_has_gateway: bool
    dns_servers: list[str]
    gateway_probe: ReachabilityProbe | None
    public_probes: list[ReachabilityProbe]
    system_dns: list[DnsProbe]
    direct_dns: list[DnsProbe]
    http_probes: list[HttpProbe]
    regional_services: list[RegionalServiceProbe]
    performance: PerformanceView | None
    cause: CauseAssessment
    platform: str = "unknown"
    collection_warnings: list[str] = field(default_factory=list)
    proxy_detected: bool = False
    dns_servers_system: list[str] = field(default_factory=list)
    duration_ms: float = 0.0


def run_command(args: list[str], timeout: float = 3.0) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True, encoding="utf-8", errors="replace",
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, "", str(exc)


def parse_default_routes(netstat_output: str) -> list[RouteEntry]:
    routes: list[RouteEntry] = []
    in_inet_section = False

    for raw_line in netstat_output.splitlines():
        line = raw_line.rstrip()
        if line == "Internet:":
            in_inet_section = True
            continue
        if not in_inet_section or not line or line.startswith("Destination"):
            continue
        if raw_line.startswith("Internet6:"):
            break

        parts = line.split()
        if len(parts) < 4 or parts[0] != "default":
            continue
        routes.append(RouteEntry(gateway=parts[1], flags=parts[2], netif=parts[3]))

    return routes


def parse_ifconfig(ifconfig_output: str) -> dict[str, InterfaceInfo]:
    interfaces: dict[str, InterfaceInfo] = {}
    current: InterfaceInfo | None = None

    for raw_line in ifconfig_output.splitlines():
        if not raw_line.startswith("\t") and raw_line and ":" in raw_line:
            name = raw_line.split(":", 1)[0]
            current = InterfaceInfo(name=name)
            interfaces[name] = current
            continue

        if current is None:
            continue

        line = raw_line.strip()
        if line.startswith("status:"):
            current.status = line.split(":", 1)[1].strip()
        elif line.startswith("inet "):
            ipv4 = line.split()[1]
            if ipv4 != "127.0.0.1":
                current.ipv4.append(ipv4)
        elif line.startswith("inet6 "):
            ipv6 = line.split()[1]
            current.ipv6.append(ipv6)
        elif line.startswith("ether "):
            current.mac = line.split()[1]

    return interfaces


def parse_arp_table(arp_output: str) -> set[str]:
    ips: set[str] = set()
    for line in arp_output.splitlines():
        match = re.search(r"\(([^)]+)\)", line)
        if match:
            ips.add(match.group(1))
    return ips


def extract_interface_block(ifconfig_output: str, interface_name: str) -> str:
    lines = ifconfig_output.splitlines()
    collecting = False
    block: list[str] = []
    prefix = f"{interface_name}:"

    for line in lines:
        if not line.startswith("\t") and line.startswith(prefix):
            collecting = True
            block.append(line)
            continue
        if collecting and not line.startswith("\t"):
            break
        if collecting:
            block.append(line)

    return "\n".join(block)


def parse_interface_counters_from_text(text: str, source: str) -> InterfaceCounters | None:
    patterns = [
        (r"input bytes (\d+)", r"output bytes (\d+)"),
        (r"RX bytes[: ](\d+)", r"TX bytes[: ](\d+)"),
        (r"ibytes[: ](\d+)", r"obytes[: ](\d+)"),
    ]
    for rx_pattern, tx_pattern in patterns:
        rx_match = re.search(rx_pattern, text, re.IGNORECASE)
        tx_match = re.search(tx_pattern, text, re.IGNORECASE)
        if rx_match and tx_match:
            return InterfaceCounters(
                rx_bytes=int(rx_match.group(1)),
                tx_bytes=int(tx_match.group(1)),
                source=source,
            )
    return None


def classify_connect_error(error_code: int) -> str:
    if error_code == 0:
        return "connected"
    if error_code in (errno.ECONNREFUSED, 10061):
        return "refused_but_host_reachable"
    if error_code in LIKELY_UNREACHABLE_ERRORS:
        return "unreachable"
    return "error"


def tcp_probe(host: str, ports: list[int], timeout: float) -> ReachabilityProbe:
    attempts: list[PortProbe] = []

    for port in ports:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        started = monotonic_ms()
        error_code: int | None = None
        detail: str | None = None

        try:
            error_code = sock.connect_ex((host, port))
        except OSError as exc:
            error_code = exc.errno or errno.EIO
            detail = str(exc)
        finally:
            latency_ms = round(monotonic_ms() - started, 1)
            sock.close()

        reachable = error_code in RECOVERABLE_CONNECT_ERRORS
        outcome = classify_connect_error(error_code or 0)
        attempts.append(
            PortProbe(
                port=port,
                reachable=reachable,
                latency_ms=latency_ms,
                outcome=outcome,
                error_code=error_code,
                detail=detail,
            )
        )
        if reachable:
            return ReachabilityProbe(
                target=host,
                reachable=True,
                latency_ms=latency_ms,
                outcome=outcome,
                detail=f"{host}:{port} {outcome}",
                attempts=attempts,
            )

    final = attempts[-1]
    return ReachabilityProbe(
        target=host,
        reachable=False,
        latency_ms=final.latency_ms,
        outcome=final.outcome,
        detail=f"{host} not reachable via tested TCP ports",
        attempts=attempts,
    )


def dns_encode_name(name: str) -> bytes:
    parts = [label.encode("idna") for label in name.rstrip(".").split(".") if label]
    return b"".join(struct.pack("!B", len(part)) + part for part in parts) + b"\x00"


def dns_query(server: str, name: str, timeout: float) -> DnsProbe:
    query_id = random.randint(0, 65535)
    flags = 0x0100
    header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)
    question = dns_encode_name(name) + struct.pack("!HH", 1, 1)
    packet = header + question

    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)

    started = monotonic_ms()
    try:
        sock.connect((server, 53))
        sock.send(packet)
        readable, _, _ = select.select([sock], [], [], timeout)
        if not readable:
            return DnsProbe(server=server, name=name, ok=False, latency_ms=None, error="timeout")

        response = sock.recv(512)
        latency_ms = round(monotonic_ms() - started, 1)
        if len(response) < 12:
            return DnsProbe(server=server, name=name, ok=False, latency_ms=latency_ms, error="short response")

        resp_id, response_flags, _, answer_count, _, _ = struct.unpack("!HHHHHH", response[:12])
        if not response_flags & 0x8000 or response_flags & 0x0200:
            return DnsProbe(server, name, False, latency_ms, error="invalid or truncated UDP DNS response")
        rcode = response[3] & 0x0F
        if resp_id != query_id:
            return DnsProbe(server=server, name=name, ok=False, latency_ms=latency_ms, error="transaction id mismatch")
        return DnsProbe(
            server=server,
            name=name,
            ok=rcode == 0 and answer_count > 0,
            latency_ms=latency_ms,
            answer_count=answer_count,
            rcode=rcode,
            error=None if rcode == 0 else f"rcode={rcode}",
        )
    except OSError as exc:
        return DnsProbe(server=server, name=name, ok=False, latency_ms=None, error=str(exc))
    finally:
        sock.close()


_resolver_slots = threading.BoundedSemaphore(4)


def run_with_timeout(func: Any, timeout: float) -> tuple[bool, Any]:
    if not _resolver_slots.acquire(blocking=False):
        return False, TimeoutError("system resolver is still busy with earlier requests")
    result: dict[str, Any] = {}

    def worker() -> None:
        try:
            result["value"] = func()
        except Exception as exc:  # noqa: BLE001
            result["error"] = exc
        finally:
            _resolver_slots.release()

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)

    if thread.is_alive():
        return False, TimeoutError(f"timeout after {timeout:.1f}s")
    if "error" in result:
        return False, result["error"]
    return True, result.get("value")


def system_dns_lookup(name: str, timeout: float) -> DnsProbe:
    started = monotonic_ms()

    def do_lookup() -> list[Any]:
        return socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)

    ok, value = run_with_timeout(do_lookup, timeout=timeout)
    latency_ms = round(monotonic_ms() - started, 1)

    if not ok:
        return DnsProbe(server="system", name=name, ok=False, latency_ms=None, error=str(value))

    answers = value or []
    return DnsProbe(server="system", name=name, ok=bool(answers), latency_ms=latency_ms, answer_count=len(answers))


def http_probe(url: str, timeout: float) -> HttpProbe:
    started = monotonic_ms()
    request = urllib.request.Request(url, headers={"User-Agent": "NetWatch/3.0"})

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            latency_ms = round(monotonic_ms() - started, 1)
            return HttpProbe(
                url=url,
                ok=200 <= response.status < 400,
                latency_ms=latency_ms,
                status_code=response.status,
            )
    except urllib.error.HTTPError as exc:
        latency_ms = round(monotonic_ms() - started, 1)
        return HttpProbe(url=url, ok=False, latency_ms=latency_ms, status_code=exc.code, error=str(exc))
    except Exception as exc:  # noqa: BLE001
        return HttpProbe(url=url, ok=False, latency_ms=None, error=str(exc))


def regional_service_probe(item: tuple[str, str, str, str], timeout: float) -> RegionalServiceProbe:
    code, region, name, url = item
    probe = http_probe(url, timeout)
    return RegionalServiceProbe(
        code=code,
        region=region,
        name=name,
        url=url,
        ok=probe.ok,
        latency_ms=probe.latency_ms,
        status_code=probe.status_code,
        error=probe.error,
    )


def build_speedtest_url(template: str, bytes_count: int) -> str:
    if "{bytes}" in template:
        return template.replace("{bytes}", str(bytes_count))
    return template


def measure_download_speed(url: str, timeout: float, max_bytes: int = 5_000_000) -> SpeedTestProbe:
    from urllib.parse import urlsplit
    request = urllib.request.Request(url, headers={"User-Agent": "NetWatch/3.0", "Accept-Encoding": "identity"})
    started = time.monotonic()
    transferred = 0
    ttfb = None
    error = None
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            ttfb = round((time.monotonic() - started) * 1000, 1)
            while transferred < max_bytes:
                if time.monotonic() - started >= timeout:
                    raise TimeoutError("download deadline exceeded")
                chunk = response.read1(min(64 * 1024, max_bytes - transferred))
                if not chunk:
                    break
                transferred += len(chunk)
        if not transferred:
            raise ValueError("empty download")
    except Exception as exc:
        error = str(exc)
    duration = max(.001, time.monotonic() - started)
    return SpeedTestProbe(
        provider=urlsplit(url).hostname or "custom", label="HTTP download", url=url,
        ok=error is None, download_mbps=round(transferred * 8 / duration / 1_000_000, 2) if error is None else None,
        transferred_bytes=transferred, duration_s=round(duration, 3), ttfb_ms=ttfb,
        measured_at=iso_now(), error=error,
    )


def compute_interface_rates(
    previous_counters: InterfaceCounters | None,
    previous_ts: float | None,
    current_counters: InterfaceCounters | None,
    current_ts: float,
) -> InterfaceRates | None:
    if (
        previous_counters is None
        or current_counters is None
        or previous_ts is None
        or previous_counters.rx_bytes is None
        or previous_counters.tx_bytes is None
        or current_counters.rx_bytes is None
        or current_counters.tx_bytes is None
    ):
        return None

    interval_s = current_ts - previous_ts
    if interval_s <= 0:
        return None

    rx_delta = current_counters.rx_bytes - previous_counters.rx_bytes
    tx_delta = current_counters.tx_bytes - previous_counters.tx_bytes
    if rx_delta < 0 or tx_delta < 0:
        return None

    return InterfaceRates(
        rx_mbps=round((rx_delta * 8) / (interval_s * 1_000_000), 3),
        tx_mbps=round((tx_delta * 8) / (interval_s * 1_000_000), 3),
        interval_s=round(interval_s, 2),
        source=current_counters.source,
    )


def choose_local_default(routes: list[RouteEntry]) -> RouteEntry | None:
    for route in routes:
        if not route.netif.startswith("utun"):
            return route
    return routes[0] if routes else None


def choose_active_default(routes: list[RouteEntry]) -> RouteEntry | None:
    return routes[0] if routes else None


def summarize_probe_counts(probes: list[Any], attr: str = "ok") -> tuple[int, int]:
    total = len(probes)
    successes = sum(1 for probe in probes if getattr(probe, attr))
    return successes, total


def regional_health_summary(probes: list[RegionalServiceProbe]) -> tuple[int, int]:
    return summarize_probe_counts(probes, "ok")


def culprit_for_code(code: str) -> str:
    mapping = {
        "healthy": "Сеть в норме",
        "no_active_interface": "Устройство / интерфейс",
        "local_interface_down": "Устройство / сетевой адаптер",
        "no_default_route": "Маршрутизация / DHCP",
        "gateway_unreachable": "Wi-Fi роутер / локальный линк",
        "upstream_wan_failure": "Мобильный оператор / uplink / апстрим",
        "local_dns_failure": "Системный DNS",
        "upstream_dns_failure": "DNS выше роутера / оператор",
        "http_layer_failure": "HTTP/TLS / фильтрация",
        "selective_upstream_instability": "Оператор / выборочная маршрутизация",
        "tunnel_or_vpn_failure": "VPN / туннель / Private Relay",
        "proxy_path": "Прямой путь / прокси",
        "direct_tcp_unavailable": "Прямой TCP / фильтрация",
        "direct_dns_restricted": "Прямой UDP DNS / ограничения сети",
        "service_partial": "Отдельные сервисы",
        "collection_limited": "Ограничения системных данных",
        "insufficient_checks": "Настройки проверок",
    }
    return mapping.get(code, "Не определено")


def make_assessment(
    status: str,
    code: str,
    summary: str,
    confidence: float,
    evidence: list[str],
    next_steps: list[str],
) -> CauseAssessment:
    return CauseAssessment(
        status=status,
        code=code,
        summary=summary,
        confidence=confidence,
        culprit=culprit_for_code(code),
        evidence=evidence,
        next_steps=next_steps,
    )


def build_assessment(snapshot: Snapshot) -> CauseAssessment:
    from .diagnosis import assess
    return assess(snapshot)


def snapshot_to_json(snapshot: Snapshot) -> dict[str, Any]:
    return asdict(snapshot)


def format_latency(latency_ms: float | None) -> str:
    return "-" if latency_ms is None else f"{latency_ms:.1f}ms"


def format_mbps(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f} Mbps"


def write_json_line(path: Path | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def parse_public_endpoints(raw_values: list[str] | None) -> list[tuple[str, str, list[int]]]:
    if not raw_values:
        return DEFAULT_PUBLIC_ENDPOINTS
    import ipaddress
    endpoints = []
    for index, raw in enumerate(raw_values, 1):
        try:
            host, port_text = raw.rsplit(":", 1)
            host = host.strip("[]")
            ipaddress.ip_address(host)
            ports = [int(value) for value in port_text.split(",")]
            if not 1 <= len(ports) <= 4 or any(not 1 <= port <= 65535 for port in ports):
                raise ValueError("invalid port")
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"Некорректная IP-точка {raw!r}; формат: 1.1.1.1:443 или [2606:4700::1111]:443"
            ) from exc
        endpoints.append((f"custom_{index}", host, ports))
    return endpoints
