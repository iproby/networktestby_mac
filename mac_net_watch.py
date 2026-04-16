#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import curses
import errno
import json
import random
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import textwrap
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
RECOVERABLE_CONNECT_ERRORS = {0, errno.ECONNREFUSED}
LIKELY_UNREACHABLE_ERRORS = {
    errno.ETIMEDOUT,
    errno.EHOSTUNREACH,
    errno.ENETUNREACH,
    errno.EHOSTDOWN,
    errno.ENETDOWN,
    errno.EADDRNOTAVAIL,
}
COLOR_DEFAULT = 1
COLOR_OK = 2
COLOR_WARN = 3
COLOR_DOWN = 4
COLOR_ACCENT = 5
COLOR_MUTED = 6
DEFAULT_CLOUDFLARE_SPEED_URL = "https://speed.cloudflare.com/__down?bytes={bytes}"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat(timespec="seconds")


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


@dataclass
class Incident:
    started_at: str
    first_cause: CauseAssessment
    last_cause: CauseAssessment
    samples: int = 0
    cause_counts: dict[str, int] = field(default_factory=dict)
    culprit_counts: dict[str, int] = field(default_factory=dict)


@dataclass
class SessionStats:
    started_at: str
    total_samples: int = 0
    ok_samples: int = 0
    degraded_samples: int = 0
    incidents_opened: int = 0
    incidents_closed: int = 0
    culprit_counts: dict[str, int] = field(default_factory=dict)
    recent_statuses: list[str] = field(default_factory=list)
    recent_events: list[str] = field(default_factory=list)
    recent_confidence: list[float] = field(default_factory=list)
    recent_geo_scores: list[int] = field(default_factory=list)
    recent_dns_scores: list[int] = field(default_factory=list)
    recent_speed_scores: list[float] = field(default_factory=list)
    completed_incidents: list[dict[str, Any]] = field(default_factory=list)
    last_snapshot: Snapshot | None = None


def run_command(args: list[str], timeout: float = 3.0) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
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


def read_interface_counters(interface_name: str | None, ifconfig_output: str) -> InterfaceCounters | None:
    if not interface_name:
        return None

    block = extract_interface_block(ifconfig_output, interface_name)
    counters = parse_interface_counters_from_text(block, "ifconfig")
    if counters is not None:
        return counters

    rc, stdout, _ = run_command(["netstat", "-ibn", "-I", interface_name], timeout=2.0)
    if rc == 0:
        lines = [line for line in stdout.splitlines() if line.strip()]
        if len(lines) >= 2:
            header = lines[0].split()
            for row in lines[1:]:
                parts = row.split()
                if len(parts) < len(header):
                    continue
                try:
                    ib_index = header.index("Ibytes")
                    ob_index = header.index("Obytes")
                    return InterfaceCounters(
                        rx_bytes=int(parts[ib_index]),
                        tx_bytes=int(parts[ob_index]),
                        source="netstat",
                    )
                except (ValueError, IndexError):
                    continue

    return None


def read_dns_servers() -> list[str]:
    servers: list[str] = []

    rc, stdout, _ = run_command(["scutil", "--dns"], timeout=2.0)
    if rc == 0:
        for line in stdout.splitlines():
            match = re.search(r"nameserver\[\d+\]\s*:\s*(\S+)", line)
            if match:
                servers.append(match.group(1))

    if not servers:
        resolv_conf = Path("/etc/resolv.conf")
        if resolv_conf.exists():
            for line in resolv_conf.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped.startswith("nameserver "):
                    servers.append(stripped.split()[1])

    seen: set[str] = set()
    unique_servers: list[str] = []
    for server in servers:
        if server not in seen:
            seen.add(server)
            unique_servers.append(server)

    return unique_servers


def classify_connect_error(error_code: int) -> str:
    if error_code == 0:
        return "connected"
    if error_code == errno.ECONNREFUSED:
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

        resp_id, _, _, answer_count, _, _ = struct.unpack("!HHHHHH", response[:12])
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


def run_with_timeout(func: Any, timeout: float) -> tuple[bool, Any]:
    result: dict[str, Any] = {}

    def worker() -> None:
        try:
            result["value"] = func()
        except Exception as exc:  # noqa: BLE001
            result["error"] = exc

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
    request = urllib.request.Request(url, headers={"User-Agent": "mac-net-watch/2.0"})

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


def run_parallel_http_probes(urls: list[str], timeout: float) -> list[HttpProbe]:
    if not urls:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(urls))) as executor:
        return list(executor.map(lambda item: http_probe(item, timeout), urls))


def run_parallel_regional_probes(items: list[tuple[str, str, str, str]], timeout: float) -> list[RegionalServiceProbe]:
    if not items:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(items))) as executor:
        return list(executor.map(lambda item: regional_service_probe(item, timeout), items))


def build_speedtest_url(template: str, bytes_count: int) -> str:
    if "{bytes}" in template:
        return template.replace("{bytes}", str(bytes_count))
    return template


def measure_download_speed(url: str, timeout: float) -> SpeedTestProbe:
    request = urllib.request.Request(url, headers={"User-Agent": "mac-net-watch/2.1"})
    started = monotonic_ms()
    transferred = 0

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            ttfb_ms = round(monotonic_ms() - started, 1)
            while True:
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                transferred += len(chunk)

            duration_s = max(0.001, (monotonic_ms() - started) / 1000)
            mbps = round((transferred * 8) / (duration_s * 1_000_000), 2)
            return SpeedTestProbe(
                provider="Cloudflare",
                label="Cloudflare edge",
                url=url,
                ok=True,
                download_mbps=mbps,
                transferred_bytes=transferred,
                duration_s=round(duration_s, 2),
                ttfb_ms=ttfb_ms,
                measured_at=iso_now(),
            )
    except Exception as exc:  # noqa: BLE001
        duration_s = max(0.0, (monotonic_ms() - started) / 1000)
        return SpeedTestProbe(
            provider="Cloudflare",
            label="Cloudflare edge",
            url=url,
            ok=False,
            download_mbps=None,
            transferred_bytes=transferred,
            duration_s=round(duration_s, 2) if duration_s else None,
            ttfb_ms=None,
            measured_at=iso_now(),
            error=str(exc),
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
        "no_active_interface": "Mac / интерфейс",
        "local_interface_down": "Mac / Wi-Fi интерфейс",
        "no_default_route": "Mac / DHCP / роутер",
        "gateway_unreachable": "Wi-Fi роутер / локальный линк",
        "upstream_wan_failure": "Мобильный оператор / uplink / апстрим",
        "local_dns_failure": "DNS только на Mac",
        "upstream_dns_failure": "DNS выше роутера / оператор",
        "http_layer_failure": "HTTP/TLS / фильтрация",
        "selective_upstream_instability": "Оператор / выборочная маршрутизация",
        "tunnel_or_vpn_failure": "VPN / туннель / Private Relay",
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
    evidence: list[str] = []
    next_steps: list[str] = []

    interface = snapshot.interface
    gateway_probe = snapshot.gateway_probe
    public_ok, public_total = summarize_probe_counts(snapshot.public_probes, "reachable")
    system_dns_ok, system_dns_total = summarize_probe_counts(snapshot.system_dns)
    direct_dns_ok, direct_dns_total = summarize_probe_counts(snapshot.direct_dns)
    http_ok, http_total = summarize_probe_counts(snapshot.http_probes)
    regional_ok, regional_total = regional_health_summary(snapshot.regional_services)
    active_tunnel = snapshot.active_default and snapshot.active_default.netif.startswith("utun")

    if interface is None:
        return make_assessment(
            "degraded",
            "no_active_interface",
            "Не удалось определить активный сетевой интерфейс.",
            0.55,
            ["`ifconfig` не дал интерфейс, привязанный к default route."],
            ["Проверьте, что Wi-Fi или Ethernet действительно поднят и имеет IPv4-адрес."],
        )

    if interface.status != "active" or not interface.ipv4:
        evidence.append(f"Интерфейс {interface.name} имеет status={interface.status} и IPv4={interface.ipv4 or 'нет'}.")
        next_steps.append("Проверьте, не отключается ли Wi-Fi-адаптер или DHCP на Mac.")
        return make_assessment(
            "down",
            "local_interface_down",
            "Проблема на стороне Mac или Wi-Fi-линка: активный интерфейс потерял IP либо перешёл в inactive.",
            0.92,
            evidence,
            next_steps,
        )

    if gateway_probe is None and snapshot.local_default is None:
        evidence.append("Default route не обнаружен.")
        next_steps.append("Проверьте, выдаёт ли роутер маршрут по умолчанию через DHCP.")
        return make_assessment(
            "down",
            "no_default_route",
            "Mac не видит маршрут по умолчанию, поэтому трафик наружу некуда отправлять.",
            0.88,
            evidence,
            next_steps,
        )

    if gateway_probe is not None and not gateway_probe.reachable:
        evidence.append(f"Шлюз {gateway_probe.target} не ответил на TCP-проверки.")
        evidence.append(f"ARP-запись для шлюза {'есть' if snapshot.arp_has_gateway else 'отсутствует'}.")
        next_steps.append("Смотрите Wi-Fi-роутер, радио-линк и питание/перегрев мобильного роутера.")
        if snapshot.arp_has_gateway:
            next_steps.append("Роутер виден в локальной сети, но не обслуживает запросы: возможен зависший NAT/DHCP/DNS на роутере.")
        return make_assessment(
            "down",
            "gateway_unreachable",
            "Вероятнее всего проблема между Mac и роутером: Wi-Fi линк нестабилен или сам роутер перестаёт отвечать.",
            0.9 if not snapshot.arp_has_gateway else 0.82,
            evidence,
            next_steps,
        )

    if public_total and public_ok == 0:
        evidence.append("Локальный шлюз доступен, но ни одна внешняя IP-точка не достижима.")
        if active_tunnel:
            evidence.append(f"Активный default route идёт через туннель {snapshot.active_default.netif}.")
            next_steps.append("На Mac активен туннель/VPN. Проверьте, не рвётся ли именно он.")
            return make_assessment(
                "down",
                "tunnel_or_vpn_failure",
                "Локальная сеть жива, но интернет пропадает за пределами Mac; при активном туннеле это похоже на проблему VPN/Private Relay/корпоративного агента.",
                0.78,
                evidence,
                next_steps,
            )

        next_steps.append("Если другие устройства в той же сети продолжают работать, сравните их маршрут и DNS в момент сбоя.")
        next_steps.append("Если одновременно падают все устройства, виноват мобильный роутер или оператор uplink.")
        return make_assessment(
            "down",
            "upstream_wan_failure",
            "Шлюз доступен, но внешняя IP-связность отсутствует: вероятнее всего проблема на WAN-стороне роутера, у мобильного оператора или апстрим-фильтрации.",
            0.86,
            evidence,
            next_steps,
        )

    if public_ok > 0 and system_dns_total and system_dns_ok == 0:
        evidence.append("Выход по IP есть, но системный DNS-резолвер на Mac не отвечает.")
        if direct_dns_ok > 0:
            evidence.append("Прямой запрос к внешним DNS-серверам проходит.")
            next_steps.append("Смотрите локальные DNS-настройки macOS, DNS у роутера, VPN-профили, фильтры и proxy auto-config.")
            return make_assessment(
                "degraded",
                "local_dns_failure",
                "Интернет по IP есть, а DNS ломается только на Mac. Вероятная причина: локальная DNS-конфигурация, профиль VPN/MDM или DNS-прокси.",
                0.9,
                evidence,
                next_steps,
            )

        evidence.append("Даже прямые DNS-запросы к известным резолверам не проходят.")
        next_steps.append("С высокой вероятностью это сбой/блокировка DNS выше роутера: оператор, upstream или фильтрация.")
        return make_assessment(
            "degraded",
            "upstream_dns_failure",
            "IP-связность частично работает, но DNS недоступен даже напрямую. Это больше похоже на проблему у оператора, апстрима или на фильтрацию DNS-трафика.",
            0.8,
            evidence,
            next_steps,
        )

    if public_ok > 0 and system_dns_ok > 0 and http_total and http_ok == 0:
        evidence.append("IP и DNS доступны, но HTTP(S)-контрольные URL не открываются.")
        next_steps.append("Похоже на выборочную фильтрацию, TLS interception, captive portal или проблему конкретных сайтов.")
        return make_assessment(
            "degraded",
            "http_layer_failure",
            "Базовая сеть жива, но проблемы начинаются на уровне HTTP/TLS. Это уже не Wi-Fi и не базовый DNS.",
            0.72,
            evidence,
            next_steps,
        )

    if 0 < public_ok < public_total:
        evidence.append(f"Снаружи доступны не все контрольные IP: {public_ok}/{public_total}.")
        next_steps.append("Это похоже на выборочную маршрутизацию или нестабильный uplink у оператора.")
        return make_assessment(
            "degraded",
            "selective_upstream_instability",
            "Связность нестабильна не полностью, а выборочно. Часто так выглядит деградация у мобильного оператора или upstream-фильтрация.",
            0.75,
            evidence,
            next_steps,
        )

    evidence.append(
        f"Интерфейс {interface.name} активен, шлюз доступен, внешние IP={public_ok}/{public_total}, system DNS={system_dns_ok}/{system_dns_total}, HTTP={http_ok}/{http_total}, регионы={regional_ok}/{regional_total}."
    )
    next_steps.append("Если проблема редкая, оставьте монитор работать на несколько часов и анализируйте инциденты по журналу.")
    return make_assessment(
        "ok",
        "healthy",
        "На момент проверки сеть выглядит исправной.",
        0.98,
        evidence,
        next_steps,
    )


def snapshot_to_json(snapshot: Snapshot) -> dict[str, Any]:
    return asdict(snapshot)


def sample_network(args: argparse.Namespace) -> Snapshot:
    sampled_at_monotonic = time.monotonic()
    _, netstat_out, _ = run_command(["netstat", "-rn", "-f", "inet"], timeout=2.0)
    _, ifconfig_out, _ = run_command(["ifconfig"], timeout=2.0)
    _, arp_out, _ = run_command(["arp", "-an"], timeout=2.0)

    routes = parse_default_routes(netstat_out)
    interfaces = parse_ifconfig(ifconfig_out)
    active_default = choose_active_default(routes)
    local_default = choose_local_default(routes)
    tunnel_defaults = [route for route in routes if route.netif.startswith("utun")]

    interface = None
    if local_default and local_default.netif in interfaces:
        interface = interfaces[local_default.netif]
    elif active_default and active_default.netif in interfaces:
        interface = interfaces[active_default.netif]
    interface_counters = read_interface_counters(interface.name if interface else None, ifconfig_out)

    arp_ips = parse_arp_table(arp_out)
    dns_servers = args.dns_server or read_dns_servers()

    gateway_probe = None
    if local_default and re.match(r"^\d+\.\d+\.\d+\.\d+$", local_default.gateway):
        gateway_probe = tcp_probe(local_default.gateway, args.gateway_ports, args.timeout)

    public_probes = [
        tcp_probe(host, ports, args.timeout)
        for _, host, ports in args.public_endpoint
    ]

    system_dns = [system_dns_lookup(name, args.timeout) for name in args.dns_name]

    direct_dns: list[DnsProbe] = []
    for name in args.dns_name:
        for server in dns_servers[: args.max_dns_servers]:
            direct_dns.append(dns_query(server, name, timeout=args.timeout))

    http_probes = run_parallel_http_probes(args.http_url, args.timeout)
    regional_services = run_parallel_regional_probes(args.regional_service, args.timeout)

    provisional = Snapshot(
        timestamp=iso_now(),
        active_default=active_default,
        local_default=local_default,
        tunnel_defaults=tunnel_defaults,
        interface=interface,
        arp_has_gateway=bool(local_default and local_default.gateway in arp_ips),
        dns_servers=dns_servers,
        gateway_probe=gateway_probe,
        public_probes=public_probes,
        system_dns=system_dns,
        direct_dns=direct_dns,
        http_probes=http_probes,
        regional_services=regional_services,
        performance=PerformanceView(interface_counters=interface_counters),
        cause=make_assessment("degraded", "unknown", "Диагностика в процессе.", 0.0, [], []),
    )
    provisional.cause = build_assessment(provisional)
    setattr(provisional, "_sampled_at_monotonic", sampled_at_monotonic)
    return provisional


def format_latency(latency_ms: float | None) -> str:
    return "-" if latency_ms is None else f"{latency_ms:.1f}ms"


def format_mbps(value: float | None) -> str:
    return "-" if value is None else f"{value:.2f} Mbps"


def format_route(route: RouteEntry | None) -> str:
    if route is None:
        return "none"
    return f"{route.gateway} via {route.netif}"


def speedtest_age_seconds(snapshot_time: str, probe: SpeedTestProbe | None) -> float | None:
    if probe is None:
        return None
    try:
        current = datetime.fromisoformat(snapshot_time)
        measured = datetime.fromisoformat(probe.measured_at)
        return max(0.0, (current - measured).total_seconds())
    except ValueError:
        return None


def format_snapshot(snapshot: Snapshot) -> str:
    public_ok, public_total = summarize_probe_counts(snapshot.public_probes, "reachable")
    system_dns_ok, system_dns_total = summarize_probe_counts(snapshot.system_dns)
    direct_dns_ok, direct_dns_total = summarize_probe_counts(snapshot.direct_dns)
    http_ok, http_total = summarize_probe_counts(snapshot.http_probes)
    regional_ok, regional_total = regional_health_summary(snapshot.regional_services)
    gateway = snapshot.gateway_probe
    gateway_status = "n/a"
    if gateway is not None:
        gateway_status = "ok" if gateway.reachable else gateway.outcome

    lines = [
        f"[{snapshot.timestamp}] status={snapshot.cause.status.upper()} cause={snapshot.cause.code} confidence={snapshot.cause.confidence:.2f}",
        f"  culprit: {snapshot.cause.culprit}",
        f"  summary: {snapshot.cause.summary}",
        f"  active_default: {format_route(snapshot.active_default)}",
        f"  local_default: {format_route(snapshot.local_default)}",
    ]

    if snapshot.interface is not None:
        lines.append(
            f"  interface: {snapshot.interface.name} status={snapshot.interface.status} ipv4={','.join(snapshot.interface.ipv4) or 'none'}"
        )

    lines.append(f"  gateway: {gateway_status} arp={'yes' if snapshot.arp_has_gateway else 'no'}")
    lines.append(
        f"  external_ip: {public_ok}/{public_total}  dns(system): {system_dns_ok}/{system_dns_total}  dns(direct): {direct_dns_ok}/{direct_dns_total}  http: {http_ok}/{http_total}  geo: {regional_ok}/{regional_total}"
    )

    if gateway is not None and gateway.attempts:
        attempt = gateway.attempts[-1]
        lines.append(
            f"  gateway_probe: port={attempt.port} outcome={attempt.outcome} latency={format_latency(attempt.latency_ms)}"
        )

    for evidence in snapshot.cause.evidence[:3]:
        lines.append(f"  evidence: {evidence}")

    if snapshot.regional_services:
        lines.append("  regional_services:")
        for service in snapshot.regional_services:
            detail = format_latency(service.latency_ms) if service.ok else (service.error or str(service.status_code or "fail"))
            state = "ok" if service.ok else "down"
            lines.append(f"    {service.code:<2} {service.region:<14} {service.name:<12} {state:<4} {detail}")

    if snapshot.performance is not None:
        rates = snapshot.performance.interface_rates
        speed = snapshot.performance.cloudflare_speed
        running = snapshot.performance.speedtest_running
        if rates is not None:
            lines.append(
                f"  interface_speed: rx={format_mbps(rates.rx_mbps)} tx={format_mbps(rates.tx_mbps)} source={rates.source or 'n/a'} interval={rates.interval_s or '-'}s"
            )
        elif snapshot.performance.interface_counters is not None:
            lines.append(
                f"  interface_speed: awaiting second sample (source={snapshot.performance.interface_counters.source or 'n/a'})"
            )

        if speed is not None:
            age = speedtest_age_seconds(snapshot.timestamp, speed)
            age_text = "-" if age is None else f"{age:.0f}s ago"
            if speed.ok:
                lines.append(
                    f"  cloudflare_speed: {format_mbps(speed.download_mbps)} ttfb={format_latency(speed.ttfb_ms)} bytes={speed.transferred_bytes} age={age_text}"
                )
            else:
                lines.append(
                    f"  cloudflare_speed: fail error={speed.error or 'unknown'} age={age_text}"
                )
        elif running:
            lines.append("  cloudflare_speed: running...")

    return "\n".join(lines)


def open_incident(snapshot: Snapshot) -> Incident:
    incident = Incident(started_at=snapshot.timestamp, first_cause=snapshot.cause, last_cause=snapshot.cause)
    add_incident_sample(incident, snapshot.cause)
    return incident


def add_incident_sample(incident: Incident, cause: CauseAssessment) -> None:
    incident.samples += 1
    incident.last_cause = cause
    incident.cause_counts[cause.code] = incident.cause_counts.get(cause.code, 0) + 1
    incident.culprit_counts[cause.culprit] = incident.culprit_counts.get(cause.culprit, 0) + 1


def dominant_cause(incident: Incident) -> str:
    if not incident.cause_counts:
        return incident.last_cause.code
    return max(incident.cause_counts.items(), key=lambda item: item[1])[0]


def dominant_culprit(incident: Incident) -> str:
    if not incident.culprit_counts:
        return incident.last_cause.culprit
    return max(incident.culprit_counts.items(), key=lambda item: item[1])[0]


def incident_duration_seconds(started_at: str, ended_at: str) -> float:
    start = datetime.fromisoformat(started_at)
    end = datetime.fromisoformat(ended_at)
    return max(0.0, (end - start).total_seconds())


def write_json_line(path: Path | None, payload: dict[str, Any]) -> None:
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


def parse_public_endpoints(raw_values: list[str] | None) -> list[tuple[str, str, list[int]]]:
    if not raw_values:
        return DEFAULT_PUBLIC_ENDPOINTS

    endpoints: list[tuple[str, str, list[int]]] = []
    for index, raw in enumerate(raw_values, start=1):
        parts = raw.split(":")
        if len(parts) < 2:
            raise argparse.ArgumentTypeError(
                f"invalid --public-endpoint '{raw}', expected host:port[,port]"
            )
        host = parts[0]
        ports = [int(value) for value in ",".join(parts[1:]).split(",") if value]
        endpoints.append((f"custom_{index}", host, ports))
    return endpoints


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Непрерывная диагностика сети на macOS с попыткой локализовать причину сбоев."
    )
    parser.add_argument("--interval", type=float, default=5.0, help="Пауза между циклами, секунд.")
    parser.add_argument("--timeout", type=float, default=2.0, help="Таймаут одной проверки, секунд.")
    parser.add_argument("--once", action="store_true", help="Сделать один цикл и завершиться.")
    parser.add_argument(
        "--log-file",
        default="network-diagnostics.jsonl",
        help="Путь к JSONL-журналу. Укажите пустую строку для отключения.",
    )
    parser.add_argument(
        "--dns-server",
        action="append",
        help="Явно добавить DNS-сервер для прямых проверок. Можно указать несколько раз.",
    )
    parser.add_argument(
        "--dns-name",
        action="append",
        default=[],
        help="Имя для DNS-проверки. Можно указать несколько раз.",
    )
    parser.add_argument(
        "--http-url",
        action="append",
        default=[],
        help="URL для HTTP(S)-контроля. Можно указать несколько раз.",
    )
    parser.add_argument(
        "--regional-service",
        action="append",
        default=[],
        help="Региональный сервис в формате CODE|Регион|Имя|URL.",
    )
    parser.add_argument(
        "--public-endpoint",
        action="append",
        default=[],
        help="Внешняя контрольная IP-точка в формате host:port[,port].",
    )
    parser.add_argument(
        "--gateway-port",
        action="append",
        type=int,
        default=[],
        help="TCP-порт для проверки локального шлюза. По умолчанию 53,80,443.",
    )
    parser.add_argument(
        "--max-dns-servers",
        type=int,
        default=3,
        help="Сколько DNS-серверов использовать для прямых запросов за цикл.",
    )
    parser.add_argument(
        "--speedtest-interval",
        type=float,
        default=120.0,
        help="Как часто запускать замер скорости до Cloudflare edge, секунд.",
    )
    parser.add_argument(
        "--speedtest-timeout",
        type=float,
        default=20.0,
        help="Таймаут speedtest-запроса, секунд.",
    )
    parser.add_argument(
        "--speedtest-bytes",
        type=int,
        default=5_000_000,
        help="Сколько байт качать при замере скорости до Cloudflare.",
    )
    parser.add_argument(
        "--speedtest-url",
        default=DEFAULT_CLOUDFLARE_SPEED_URL,
        help="URL-шаблон замера скорости. Можно использовать {bytes}.",
    )
    parser.add_argument("--json", action="store_true", help="Печатать snapshot в JSON, а не в текстовом виде.")
    parser.add_argument("--plain", action="store_true", help="Отключить полноэкранный интерфейс и печатать текстом.")
    return parser


def normalize_args(args: argparse.Namespace) -> argparse.Namespace:
    args.gateway_ports = args.gateway_port or [53, 80, 443]
    args.dns_name = args.dns_name or list(DEFAULT_DNS_NAMES)
    args.http_url = args.http_url or list(DEFAULT_HTTP_URLS)
    args.public_endpoint = parse_public_endpoints(args.public_endpoint)
    if args.regional_service:
        parsed_services: list[tuple[str, str, str, str]] = []
        for raw in args.regional_service:
            parts = raw.split("|", 3)
            if len(parts) != 4:
                raise SystemExit(
                    f"invalid --regional-service '{raw}', expected CODE|Регион|Имя|URL"
                )
            parsed_services.append((parts[0], parts[1], parts[2], parts[3]))
        args.regional_service = parsed_services
    else:
        args.regional_service = list(DEFAULT_REGIONAL_SERVICES)
    args.log_file = None if args.log_file == "" else Path(args.log_file).expanduser()
    return args


def print_incident_closed(incident: Incident, recovered_at: str) -> None:
    duration = incident_duration_seconds(incident.started_at, recovered_at)
    dominant = dominant_cause(incident)
    culprit = dominant_culprit(incident)
    print(
        f"[{recovered_at}] RECOVERED after {duration:.1f}s, dominant_cause={dominant}, culprit={culprit}, samples={incident.samples}",
        flush=True,
    )


def append_recent(items: list[Any], value: Any, limit: int) -> None:
    items.append(value)
    if len(items) > limit:
        del items[0 : len(items) - limit]


def record_session_sample(stats: SessionStats, snapshot: Snapshot) -> None:
    geo_ok, geo_total = regional_health_summary(snapshot.regional_services)
    dns_ok, dns_total = summarize_probe_counts(snapshot.system_dns)
    speed_value = 0.0
    if snapshot.performance and snapshot.performance.cloudflare_speed and snapshot.performance.cloudflare_speed.download_mbps:
        speed_value = snapshot.performance.cloudflare_speed.download_mbps

    stats.total_samples += 1
    if snapshot.cause.status == "ok":
        stats.ok_samples += 1
    else:
        stats.degraded_samples += 1
    stats.last_snapshot = snapshot
    stats.culprit_counts[snapshot.cause.culprit] = stats.culprit_counts.get(snapshot.cause.culprit, 0) + 1
    append_recent(stats.recent_statuses, snapshot.cause.status, 40)
    append_recent(
        stats.recent_events,
        f"{snapshot.timestamp[-8:]}  {snapshot.cause.status.upper():<8}  {snapshot.cause.culprit}",
        12,
    )
    append_recent(stats.recent_confidence, snapshot.cause.confidence, 60)
    append_recent(stats.recent_geo_scores, int((geo_ok / geo_total) * 100) if geo_total else 0, 60)
    append_recent(stats.recent_dns_scores, int((dns_ok / dns_total) * 100) if dns_total else 0, 60)
    append_recent(stats.recent_speed_scores, speed_value, 60)


def close_incident(stats: SessionStats, incident: Incident, recovered_at: str) -> dict[str, Any]:
    duration = incident_duration_seconds(incident.started_at, recovered_at)
    summary = {
        "started_at": incident.started_at,
        "ended_at": recovered_at,
        "duration_seconds": duration,
        "dominant_cause": dominant_cause(incident),
        "dominant_culprit": dominant_culprit(incident),
        "samples": incident.samples,
    }
    append_recent(
        stats.recent_events,
        f"{recovered_at[-8:]}  RECOVER   {summary['dominant_culprit']} ({duration:.0f}s)",
        12,
    )
    stats.completed_incidents.append(summary)
    if len(stats.completed_incidents) > 8:
        del stats.completed_incidents[0 : len(stats.completed_incidents) - 8]
    stats.incidents_closed += 1
    return summary


def open_incident_for_stats(stats: SessionStats, snapshot: Snapshot) -> Incident:
    incident = open_incident(snapshot)
    stats.incidents_opened += 1
    append_recent(stats.recent_events, f"{snapshot.timestamp[-8:]}  INCIDENT  {snapshot.cause.culprit}", 12)
    return incident


def write_sample_log(path: Path | None, snapshot: Snapshot) -> None:
    write_json_line(
        path,
        {
            "event": "sample",
            "snapshot": snapshot_to_json(snapshot),
        },
    )


def write_incident_open_log(path: Path | None, incident: Incident, snapshot: Snapshot) -> None:
    write_json_line(
        path,
        {
            "event": "incident_opened",
            "started_at": incident.started_at,
            "cause": asdict(snapshot.cause),
        },
    )


def write_incident_close_log(path: Path | None, incident: Incident, recovered_at: str) -> None:
    write_json_line(
        path,
        {
            "event": "incident_closed",
            "started_at": incident.started_at,
            "ended_at": recovered_at,
            "duration_seconds": incident_duration_seconds(incident.started_at, recovered_at),
            "dominant_cause": dominant_cause(incident),
            "dominant_culprit": dominant_culprit(incident),
            "samples": incident.samples,
            "first_cause": asdict(incident.first_cause),
            "last_cause": asdict(incident.last_cause),
        },
    )


def harvest_speedtest_future(
    future: concurrent.futures.Future[SpeedTestProbe] | None,
    last_result: SpeedTestProbe | None,
) -> tuple[concurrent.futures.Future[SpeedTestProbe] | None, SpeedTestProbe | None]:
    if future is None or not future.done():
        return future, last_result
    try:
        last_result = future.result()
    except Exception as exc:  # noqa: BLE001
        last_result = SpeedTestProbe(
            provider="Cloudflare",
            label="Cloudflare edge",
            url="unknown",
            ok=False,
            download_mbps=None,
            transferred_bytes=0,
            duration_s=None,
            ttfb_ms=None,
            measured_at=iso_now(),
            error=str(exc),
        )
    return None, last_result


def should_start_speedtest(
    future: concurrent.futures.Future[SpeedTestProbe] | None,
    last_result: SpeedTestProbe | None,
    now_monotonic: float,
    last_started_at: float | None,
    interval_s: float,
) -> bool:
    if future is not None:
        return False
    if last_result is None and last_started_at is None:
        return True
    reference = last_started_at
    if reference is None:
        return True
    return (now_monotonic - reference) >= interval_s


def apply_performance_view(
    snapshot: Snapshot,
    previous_counters: InterfaceCounters | None,
    previous_counter_ts: float | None,
    last_speedtest: SpeedTestProbe | None,
    speedtest_running: bool,
) -> tuple[InterfaceCounters | None, float | None]:
    current_ts = getattr(snapshot, "_sampled_at_monotonic", time.monotonic())
    current_counters = snapshot.performance.interface_counters if snapshot.performance else None
    rates = compute_interface_rates(previous_counters, previous_counter_ts, current_counters, current_ts)

    if snapshot.performance is None:
        snapshot.performance = PerformanceView()
    snapshot.performance.interface_rates = rates
    snapshot.performance.cloudflare_speed = last_speedtest
    snapshot.performance.speedtest_running = speedtest_running

    next_counters = current_counters if current_counters is not None else previous_counters
    next_ts = current_ts if current_counters is not None else previous_counter_ts
    return next_counters, next_ts


def run_plain_loop(args: argparse.Namespace) -> int:
    stop_requested = False
    active_incident: Incident | None = None
    previous_counters: InterfaceCounters | None = None
    previous_counter_ts: float | None = None
    speedtest_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    speedtest_future: concurrent.futures.Future[SpeedTestProbe] | None = None
    last_speedtest: SpeedTestProbe | None = None
    speedtest_started_at: float | None = None

    def handle_signal(signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True
        print(f"\n[{iso_now()}] received signal {signum}, stopping...", flush=True)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    while not stop_requested:
        speedtest_future, last_speedtest = harvest_speedtest_future(speedtest_future, last_speedtest)
        snapshot = sample_network(args)
        previous_counters, previous_counter_ts = apply_performance_view(
            snapshot,
            previous_counters,
            previous_counter_ts,
            last_speedtest,
            speedtest_future is not None,
        )

        current_ts = getattr(snapshot, "_sampled_at_monotonic", time.monotonic())
        if should_start_speedtest(
            speedtest_future,
            last_speedtest,
            current_ts,
            speedtest_started_at,
            args.speedtest_interval,
        ):
            speedtest_future = speedtest_executor.submit(
                measure_download_speed,
                build_speedtest_url(args.speedtest_url, args.speedtest_bytes),
                args.speedtest_timeout,
            )
            speedtest_started_at = current_ts
            if snapshot.performance is not None:
                snapshot.performance.speedtest_running = True

        if args.json:
            print(json.dumps(snapshot_to_json(snapshot), ensure_ascii=False), flush=True)
        else:
            print(format_snapshot(snapshot), flush=True)

        write_sample_log(args.log_file, snapshot)

        if snapshot.cause.status == "ok":
            if active_incident is not None:
                print_incident_closed(active_incident, snapshot.timestamp)
                write_incident_close_log(args.log_file, active_incident, snapshot.timestamp)
                active_incident = None
        else:
            if active_incident is None:
                active_incident = open_incident(snapshot)
                print(f"[{snapshot.timestamp}] INCIDENT OPEN: {snapshot.cause.summary}", flush=True)
                write_incident_open_log(args.log_file, active_incident, snapshot)
            else:
                add_incident_sample(active_incident, snapshot.cause)

        if args.once:
            break
        time.sleep(args.interval)

    speedtest_executor.shutdown(wait=False, cancel_futures=False)
    return 0


def status_label(status: str) -> str:
    return {
        "ok": "OK",
        "degraded": "WARN",
        "down": "DOWN",
    }.get(status, status.upper())


def status_color(status: str) -> int:
    return {
        "ok": COLOR_OK,
        "degraded": COLOR_WARN,
        "down": COLOR_DOWN,
    }.get(status, COLOR_DEFAULT)


def init_colors() -> None:
    if not curses.has_colors():
        return
    try:
        curses.start_color()
    except curses.error:
        return
    try:
        curses.use_default_colors()
        background = -1
    except curses.error:
        background = curses.COLOR_BLACK
    try:
        curses.init_pair(COLOR_DEFAULT, curses.COLOR_WHITE, background)
        curses.init_pair(COLOR_OK, curses.COLOR_GREEN, background)
        curses.init_pair(COLOR_WARN, curses.COLOR_YELLOW, background)
        curses.init_pair(COLOR_DOWN, curses.COLOR_RED, background)
        curses.init_pair(COLOR_ACCENT, curses.COLOR_CYAN, background)
        curses.init_pair(COLOR_MUTED, curses.COLOR_BLACK, curses.COLOR_WHITE)
    except curses.error:
        pass


def safe_addstr(win: Any, y: int, x: int, text: str, attr: int = 0) -> None:
    height, width = win.getmaxyx()
    if y < 0 or y >= height or x >= width:
        return
    available = max(0, width - x - 1)
    if available <= 0:
        return
    try:
        win.addstr(y, x, text[:available], attr)
    except curses.error:
        pass


def draw_box(win: Any, y: int, x: int, h: int, w: int, title: str, color: int = COLOR_DEFAULT) -> None:
    if h < 3 or w < 4:
        return
    try:
        attr = curses.color_pair(color)
        win.attron(attr)
        win.addstr(y, x, "╭")
        win.addstr(y, x + w - 1, "╮")
        win.addstr(y + h - 1, x, "╰")
        win.addstr(y + h - 1, x + w - 1, "╯")
        for col in range(x + 1, x + w - 1):
            win.addstr(y, col, "─")
            win.addstr(y + h - 1, col, "─")
        for row in range(y + 1, y + h - 1):
            win.addstr(row, x, "│")
            win.addstr(row, x + w - 1, "│")
        win.attroff(attr)
    except curses.error:
        return

    safe_addstr(win, y, x + 2, f" {title} ", curses.color_pair(color) | curses.A_BOLD)


def draw_wrapped(win: Any, y: int, x: int, width: int, text: str, attr: int = 0, max_lines: int | None = None) -> int:
    lines = textwrap.wrap(text, width=max(10, width)) or [""]
    if max_lines is not None:
        lines = lines[:max_lines]
    for idx, line in enumerate(lines):
        safe_addstr(win, y + idx, x, line, attr)
    return len(lines)


def one_line_probe_summary(probe: ReachabilityProbe | None) -> str:
    if probe is None:
        return "n/a"
    if probe.reachable:
        return f"ok {format_latency(probe.latency_ms)}"
    attempt = probe.attempts[-1] if probe.attempts else None
    if attempt is None:
        return probe.outcome
    return f"{attempt.outcome} {format_latency(attempt.latency_ms)}"


def summarize_dns_servers(snapshot: Snapshot) -> str:
    if not snapshot.dns_servers:
        return "none"
    return ", ".join(snapshot.dns_servers[:3])


def dominant_session_culprit(stats: SessionStats) -> str:
    if not stats.culprit_counts:
        return "Нет данных"
    return max(stats.culprit_counts.items(), key=lambda item: item[1])[0]


def sparkline(statuses: list[str], width: int) -> str:
    if width <= 0:
        return ""
    symbols = {
        "ok": "•",
        "degraded": "▲",
        "down": "✕",
    }
    tail = statuses[-width:]
    return "".join(symbols.get(item, "?") for item in tail).rjust(width)


def compact_counts(successes: int, total: int) -> str:
    return f"{successes}/{total}"


def regional_service_status_text(service: RegionalServiceProbe) -> str:
    if service.ok:
        return format_latency(service.latency_ms)
    if service.status_code is not None:
        return f"http {service.status_code}"
    return service.error or "fail"


def numeric_sparkline(values: list[float], width: int, ceiling: float | None = None) -> str:
    if width <= 0:
        return ""
    glyphs = "▁▂▃▄▅▆▇█"
    tail = values[-width:]
    prepared = [max(0.0, float(item)) for item in tail]
    if not prepared:
        return ""
    max_value = ceiling if ceiling is not None else max(prepared)
    if max_value <= 0:
        return "·" * len(prepared)
    output = []
    for value in prepared:
        index = min(len(glyphs) - 1, int(round((value / max_value) * (len(glyphs) - 1))))
        output.append(glyphs[index])
    return "".join(output).rjust(width)


def clip_text(text: str, width: int) -> str:
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 1:
        return text[:width]
    return text[: width - 1] + "…"


def status_icon(status: str) -> str:
    return {
        "ok": "●",
        "degraded": "▲",
        "down": "✕",
    }.get(status, "•")


def progress_bar(value: int, total: int, width: int) -> str:
    width = max(4, width)
    if total <= 0:
        return "░" * width
    filled = int(round((value / total) * width))
    filled = max(0, min(width, filled))
    return ("█" * filled) + ("░" * (width - filled))


def ratio_percent(value: int, total: int) -> int:
    if total <= 0:
        return 0
    return int(round((value / total) * 100))


def group_regional_services(probes: list[RegionalServiceProbe]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for probe in probes:
        item = grouped.setdefault(
            probe.region,
            {"region": probe.region, "ok": 0, "total": 0, "services": [], "latencies": []},
        )
        item["total"] += 1
        if probe.ok:
            item["ok"] += 1
            if probe.latency_ms is not None:
                item["latencies"].append(probe.latency_ms)
        item["services"].append(probe)

    rows = []
    for region, item in grouped.items():
        avg_latency = round(sum(item["latencies"]) / len(item["latencies"]), 1) if item["latencies"] else None
        rows.append(
            {
                "region": region,
                "ok": item["ok"],
                "total": item["total"],
                "avg_latency_ms": avg_latency,
                "services": item["services"],
            }
        )
    return rows


def health_rows(snapshot: Snapshot) -> list[dict[str, Any]]:
    public_ok, public_total = summarize_probe_counts(snapshot.public_probes, "reachable")
    system_dns_ok, system_dns_total = summarize_probe_counts(snapshot.system_dns)
    direct_dns_ok, direct_dns_total = summarize_probe_counts(snapshot.direct_dns)
    http_ok, http_total = summarize_probe_counts(snapshot.http_probes)
    geo_ok, geo_total = regional_health_summary(snapshot.regional_services)
    gateway_ok = 1 if snapshot.gateway_probe and snapshot.gateway_probe.reachable else 0
    gateway_total = 1 if snapshot.gateway_probe is not None else 0
    return [
        {"label": "Gateway", "ok": gateway_ok, "total": gateway_total, "detail": one_line_probe_summary(snapshot.gateway_probe)},
        {"label": "External IP", "ok": public_ok, "total": public_total, "detail": compact_counts(public_ok, public_total)},
        {"label": "System DNS", "ok": system_dns_ok, "total": system_dns_total, "detail": compact_counts(system_dns_ok, system_dns_total)},
        {"label": "Direct DNS", "ok": direct_dns_ok, "total": direct_dns_total, "detail": compact_counts(direct_dns_ok, direct_dns_total)},
        {"label": "HTTP", "ok": http_ok, "total": http_total, "detail": compact_counts(http_ok, http_total)},
        {"label": "Geo", "ok": geo_ok, "total": geo_total, "detail": compact_counts(geo_ok, geo_total)},
    ]


def metric_card(stdscr: Any, y: int, x: int, h: int, w: int, title: str, value: str, subtitle: str, status: str) -> None:
    color = status_color(status)
    draw_box(stdscr, y, x, h, w, title, color)
    safe_addstr(stdscr, y + 1, x + 2, value, curses.color_pair(color) | curses.A_BOLD)
    safe_addstr(stdscr, y + 2, x + 2, clip_text(subtitle, w - 4), curses.color_pair(COLOR_DEFAULT))


def draw_header(stdscr: Any, width: int, snapshot: Snapshot, stats: SessionStats) -> None:
    label = status_label(snapshot.cause.status)
    attr = curses.color_pair(status_color(snapshot.cause.status)) | curses.A_BOLD
    geo_ok, geo_total = regional_health_summary(snapshot.regional_services)
    safe_addstr(stdscr, 0, 2, "MAC NET WATCH", curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)
    safe_addstr(stdscr, 0, 18, f"{status_icon(snapshot.cause.status)} {label}", attr)
    safe_addstr(stdscr, 0, 30, f"Причина: {clip_text(snapshot.cause.culprit, max(10, width - 62))}", curses.A_BOLD)
    safe_addstr(stdscr, 0, max(2, width - 27), snapshot.timestamp, curses.color_pair(COLOR_MUTED))
    safe_addstr(
        stdscr,
        1,
        2,
        f"Сессия {stats.total_samples} samples  •  Geo {geo_ok}/{geo_total}  •  Confidence {snapshot.cause.confidence:.2f}  •  {sparkline(stats.recent_statuses, max(12, width - 78))}",
        curses.color_pair(COLOR_MUTED),
    )


def draw_metric_cards(stdscr: Any, y: int, width: int, snapshot: Snapshot, stats: SessionStats) -> None:
    geo_ok, geo_total = regional_health_summary(snapshot.regional_services)
    dns_ok, dns_total = summarize_probe_counts(snapshot.system_dns)
    public_ok, public_total = summarize_probe_counts(snapshot.public_probes, "reachable")
    speed = snapshot.performance.cloudflare_speed if snapshot.performance else None
    speed_value = format_mbps(speed.download_mbps) if speed and speed.ok else ("running…" if snapshot.performance and snapshot.performance.speedtest_running else "n/a")

    cards = [
        ("Overall", status_label(snapshot.cause.status), snapshot.cause.culprit, snapshot.cause.status),
        ("External", compact_counts(public_ok, public_total), "Reachability to public IPs", "ok" if public_total and public_ok == public_total else ("degraded" if public_ok else "down")),
        ("DNS", compact_counts(dns_ok, dns_total), "System resolver health", "ok" if dns_total and dns_ok == dns_total else ("degraded" if dns_ok else "down")),
        ("Geo", compact_counts(geo_ok, geo_total), "Regional service availability", "ok" if geo_total and geo_ok == geo_total else ("degraded" if geo_ok else "down")),
        ("Speed", speed_value, "Cloudflare edge download", "ok" if speed and speed.ok else ("degraded" if snapshot.performance and snapshot.performance.speedtest_running else "down")),
    ]

    card_w = max(18, width // len(cards))
    for index, (title, value, subtitle, status) in enumerate(cards):
        x = index * card_w
        w = card_w if index < len(cards) - 1 else width - x
        metric_card(stdscr, y, x, 4, w, title, value, subtitle, status)


def draw_story_panel(stdscr: Any, y: int, x: int, h: int, w: int, snapshot: Snapshot, stats: SessionStats, active_incident: Incident | None) -> None:
    draw_box(stdscr, y, x, h, w, "Ситуация", COLOR_ACCENT)
    row = y + 1
    body_x = x + 2
    safe_addstr(stdscr, row, body_x, f"{status_icon(snapshot.cause.status)} {snapshot.cause.summary}", curses.color_pair(status_color(snapshot.cause.status)) | curses.A_BOLD)
    row += 2
    safe_addstr(stdscr, row, body_x, f"Вероятный виновник: {snapshot.cause.culprit}", curses.A_BOLD)
    row += 1
    safe_addstr(stdscr, row, body_x, f"Доминирующий виновник по сессии: {dominant_session_culprit(stats)}")
    row += 1
    if active_incident is not None:
        duration = incident_duration_seconds(active_incident.started_at, snapshot.timestamp)
        safe_addstr(stdscr, row, body_x, f"Активный инцидент: {duration:.0f}s", curses.color_pair(COLOR_WARN) | curses.A_BOLD)
    elif stats.completed_incidents:
        last = stats.completed_incidents[-1]
        safe_addstr(stdscr, row, body_x, f"Последний инцидент: {last['dominant_culprit']} ({last['duration_seconds']:.0f}s)", curses.color_pair(COLOR_OK))
    row += 2
    safe_addstr(stdscr, row, body_x, "Почему так решили:", curses.A_BOLD)
    row += 1
    for item in snapshot.cause.evidence[: max(1, h - 11)]:
        row += draw_wrapped(stdscr, row, body_x, w - 4, f"• {item}", max_lines=2)
    if row < y + h - 2:
        row += 1
        safe_addstr(stdscr, row, body_x, "Следующий шаг:", curses.A_BOLD)
        row += 1
        if snapshot.cause.next_steps:
            draw_wrapped(stdscr, row, body_x, w - 4, f"→ {snapshot.cause.next_steps[0]}", max_lines=2)


def draw_health_matrix(stdscr: Any, y: int, x: int, h: int, w: int, snapshot: Snapshot) -> None:
    draw_box(stdscr, y, x, h, w, "Health Matrix", COLOR_DEFAULT)
    row = y + 1
    body_x = x + 2
    bar_w = max(8, w - 27)
    for item in health_rows(snapshot)[: max(0, h - 2)]:
        percent = ratio_percent(item["ok"], item["total"])
        status = "ok" if item["total"] and item["ok"] == item["total"] else ("degraded" if item["ok"] else "down")
        safe_addstr(stdscr, row, body_x, f"{item['label']:<11}", curses.A_BOLD)
        safe_addstr(stdscr, row, body_x + 12, progress_bar(item["ok"], max(1, item["total"]), bar_w), curses.color_pair(status_color(status)))
        safe_addstr(stdscr, row, body_x + 13 + bar_w, f"{percent:>3}%", curses.color_pair(status_color(status)) | curses.A_BOLD)
        row += 1
    if row < y + h - 1:
        row += 1
        safe_addstr(stdscr, row, body_x, f"DNS servers: {clip_text(summarize_dns_servers(snapshot), w - 4)}")


def draw_network_panel(stdscr: Any, y: int, x: int, h: int, w: int, snapshot: Snapshot, stats: SessionStats) -> None:
    draw_box(stdscr, y, x, h, w, "Network & Flow", COLOR_DEFAULT)
    row = y + 1
    body_x = x + 2
    interface = snapshot.interface
    safe_addstr(stdscr, row, body_x, f"Route: {clip_text(format_route(snapshot.local_default), w - 10)}", curses.A_BOLD)
    row += 1
    safe_addstr(stdscr, row, body_x, f"Active: {clip_text(format_route(snapshot.active_default), w - 10)}")
    row += 1
    if interface is not None:
        safe_addstr(stdscr, row, body_x, f"Interface: {interface.name}  IPv4 {','.join(interface.ipv4) or 'none'}")
        row += 1
    safe_addstr(stdscr, row, body_x, f"Gateway: {one_line_probe_summary(snapshot.gateway_probe)}  ARP {'yes' if snapshot.arp_has_gateway else 'no'}")
    row += 2

    if snapshot.performance is not None:
        rates = snapshot.performance.interface_rates
        speed = snapshot.performance.cloudflare_speed
        safe_addstr(stdscr, row, body_x, "Traffic now", curses.A_BOLD)
        row += 1
        if rates is not None:
            safe_addstr(stdscr, row, body_x, f"RX {format_mbps(rates.rx_mbps)}   TX {format_mbps(rates.tx_mbps)}", curses.color_pair(COLOR_ACCENT) | curses.A_BOLD)
            row += 1
        else:
            safe_addstr(stdscr, row, body_x, "RX/TX: waiting for next sample", curses.color_pair(COLOR_MUTED))
            row += 1
        if row < y + h - 4:
            safe_addstr(stdscr, row, body_x, f"Cloudflare edge: {format_mbps(speed.download_mbps) if speed and speed.ok else ('running…' if snapshot.performance.speedtest_running else 'n/a')}", curses.A_BOLD)
            row += 1
            if speed is not None:
                safe_addstr(stdscr, row, body_x, f"TTFB {format_latency(speed.ttfb_ms)}   bytes {speed.transferred_bytes}   age {clip_text(str(int(speedtest_age_seconds(snapshot.timestamp, speed) or 0)) + 's', 12)}")
                row += 1

    if row < y + h - 3:
        row += 1
        safe_addstr(stdscr, row, body_x, f"Speed trend  {numeric_sparkline(stats.recent_speed_scores, max(10, w - 16))}", curses.color_pair(COLOR_MUTED))
        row += 1
        safe_addstr(stdscr, row, body_x, f"Geo trend    {numeric_sparkline([float(v) for v in stats.recent_geo_scores], max(10, w - 16), 100)}", curses.color_pair(COLOR_MUTED))


def draw_regional_services(stdscr: Any, y: int, x: int, h: int, w: int, snapshot: Snapshot) -> None:
    draw_box(stdscr, y, x, h, w, "Geo Reachability", COLOR_DEFAULT)
    row = y + 1
    body_x = x + 2
    groups = group_regional_services(snapshot.regional_services)
    for group in groups[: max(0, h - 2)]:
        percent = ratio_percent(group["ok"], group["total"])
        status = "ok" if group["ok"] == group["total"] else ("degraded" if group["ok"] else "down")
        safe_addstr(stdscr, row, body_x, f"{clip_text(group['region'], 14):<14}", curses.A_BOLD)
        safe_addstr(stdscr, row, body_x + 15, progress_bar(group["ok"], max(1, group["total"]), 8), curses.color_pair(status_color(status)))
        latency = format_latency(group["avg_latency_ms"]) if group["avg_latency_ms"] is not None else "—"
        safe_addstr(stdscr, row, body_x + 25, f"{group['ok']}/{group['total']}  {latency}", curses.color_pair(status_color(status)))
        row += 1
    if row < y + h - 1:
        row += 1
    for service in snapshot.regional_services[: max(0, y + h - row - 1)]:
        color = curses.color_pair(status_color("ok" if service.ok else "down"))
        label = f"{service.code:<3} {clip_text(service.name, 12):<12}"
        detail = clip_text(regional_service_status_text(service), max(10, w - 22))
        safe_addstr(stdscr, row, body_x, label, curses.A_BOLD)
        safe_addstr(stdscr, row, body_x + 17, detail, color)
        row += 1


def draw_timeline_panel(stdscr: Any, y: int, x: int, h: int, w: int, stats: SessionStats, snapshot: Snapshot) -> None:
    draw_box(stdscr, y, x, h, w, "Timeline", COLOR_DEFAULT)
    row = y + 1
    body_x = x + 2
    safe_addstr(stdscr, row, body_x, f"Status  {sparkline(stats.recent_statuses, max(10, w - 12))}", curses.color_pair(COLOR_MUTED))
    row += 1
    safe_addstr(stdscr, row, body_x, f"Geo     {numeric_sparkline([float(v) for v in stats.recent_geo_scores], max(10, w - 12), 100)}", curses.color_pair(COLOR_MUTED))
    row += 1
    safe_addstr(stdscr, row, body_x, f"DNS     {numeric_sparkline([float(v) for v in stats.recent_dns_scores], max(10, w - 12), 100)}", curses.color_pair(COLOR_MUTED))
    row += 2
    for item in stats.recent_events[: max(0, h - 6)]:
        safe_addstr(stdscr, row, body_x, clip_text(item, w - 4))
        row += 1


def draw_footer(stdscr: Any, width: int, args: argparse.Namespace) -> None:
    safe_addstr(
        stdscr,
        curses.LINES - 1,
        2,
        f"q quit  •  interval {args.interval}s  •  timeout {args.timeout}s  •  speedtest {args.speedtest_interval}s  •  log {args.log_file or 'off'}",
        curses.color_pair(COLOR_MUTED),
    )
    safe_addstr(stdscr, curses.LINES - 1, max(2, width - 25), "plain --plain  json --json", curses.color_pair(COLOR_MUTED))


def render_dashboard(stdscr: Any, snapshot: Snapshot, stats: SessionStats, active_incident: Incident | None, args: argparse.Namespace) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()

    if height < 30 or width < 110:
        safe_addstr(stdscr, 1, 2, "Терминал слишком маленький для выразительного интерфейса.", curses.color_pair(COLOR_DOWN) | curses.A_BOLD)
        safe_addstr(stdscr, 3, 2, "Нужно минимум 110x30. Увеличьте окно или запустите с --plain.")
        draw_footer(stdscr, width, args)
        stdscr.refresh()
        return

    draw_header(stdscr, width, snapshot, stats)
    draw_metric_cards(stdscr, 3, width, snapshot, stats)

    top_y = 8
    top_h = 11
    left_w = width // 2
    mid_w = width // 4
    right_w = width - left_w - mid_w

    draw_story_panel(stdscr, top_y, 0, top_h, left_w, snapshot, stats, active_incident)
    draw_health_matrix(stdscr, top_y, left_w, top_h, mid_w, snapshot)
    draw_regional_services(stdscr, top_y, left_w + mid_w, top_h, right_w, snapshot)

    bottom_y = top_y + top_h
    bottom_h = height - bottom_y - 1
    bottom_left_w = width * 3 // 5
    bottom_right_w = width - bottom_left_w
    draw_network_panel(stdscr, bottom_y, 0, bottom_h, bottom_left_w, snapshot, stats)
    draw_timeline_panel(stdscr, bottom_y, bottom_left_w, bottom_h, bottom_right_w, stats, snapshot)

    draw_footer(stdscr, width, args)
    stdscr.refresh()


def sleep_with_input(stdscr: Any, seconds: float) -> str | None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        stdscr.timeout(max(50, int(min(remaining, 0.2) * 1000)))
        key = stdscr.getch()
        if key in (ord("q"), ord("Q")):
            return "quit"
        if key == curses.KEY_RESIZE:
            return "resize"
    return None


def run_dashboard(stdscr: Any, args: argparse.Namespace) -> int:
    stop_requested = False
    active_incident: Incident | None = None
    stats = SessionStats(started_at=iso_now())
    previous_counters: InterfaceCounters | None = None
    previous_counter_ts: float | None = None
    speedtest_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    speedtest_future: concurrent.futures.Future[SpeedTestProbe] | None = None
    last_speedtest: SpeedTestProbe | None = None
    speedtest_started_at: float | None = None

    def handle_signal(signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True
        append_recent(stats.recent_events, f"{iso_now()[-8:]}  SIGNAL    {signum}", 12)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        curses.curs_set(0)
    except curses.error:
        pass
    stdscr.nodelay(False)
    init_colors()

    while not stop_requested:
        speedtest_future, last_speedtest = harvest_speedtest_future(speedtest_future, last_speedtest)
        snapshot = sample_network(args)
        previous_counters, previous_counter_ts = apply_performance_view(
            snapshot,
            previous_counters,
            previous_counter_ts,
            last_speedtest,
            speedtest_future is not None,
        )
        current_ts = getattr(snapshot, "_sampled_at_monotonic", time.monotonic())
        if should_start_speedtest(
            speedtest_future,
            last_speedtest,
            current_ts,
            speedtest_started_at,
            args.speedtest_interval,
        ):
            speedtest_future = speedtest_executor.submit(
                measure_download_speed,
                build_speedtest_url(args.speedtest_url, args.speedtest_bytes),
                args.speedtest_timeout,
            )
            speedtest_started_at = current_ts
            if snapshot.performance is not None:
                snapshot.performance.speedtest_running = True
        record_session_sample(stats, snapshot)
        write_sample_log(args.log_file, snapshot)

        if snapshot.cause.status == "ok":
            if active_incident is not None:
                close_incident(stats, active_incident, snapshot.timestamp)
                write_incident_close_log(args.log_file, active_incident, snapshot.timestamp)
                active_incident = None
        else:
            if active_incident is None:
                active_incident = open_incident_for_stats(stats, snapshot)
                write_incident_open_log(args.log_file, active_incident, snapshot)
            else:
                add_incident_sample(active_incident, snapshot.cause)

        render_dashboard(stdscr, snapshot, stats, active_incident, args)

        if args.once:
            sleep_with_input(stdscr, 0.7)
            break

        action = sleep_with_input(stdscr, args.interval)
        if action == "quit":
            break

    speedtest_executor.shutdown(wait=False, cancel_futures=False)
    return 0


def should_use_dashboard(args: argparse.Namespace) -> bool:
    if args.plain or args.json:
        return False
    return sys.stdout.isatty() and sys.stdin.isatty()


def main() -> int:
    parser = build_parser()
    args = normalize_args(parser.parse_args())

    if should_use_dashboard(args):
        return curses.wrapper(lambda stdscr: run_dashboard(stdscr, args))
    return run_plain_loop(args)


if __name__ == "__main__":
    sys.exit(main())
