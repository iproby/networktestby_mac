"""Read-only native routing/DNS adapters; no elevated privileges or shell parsing."""
from __future__ import annotations

import ipaddress
import json
import platform
import re
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from .core import InterfaceCounters, InterfaceInfo, RouteEntry, parse_default_routes, run_command


@dataclass
class NativeState:
    platform: str
    interfaces: dict[str, InterfaceInfo] = field(default_factory=dict)
    routes: list[RouteEntry] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    counters: dict[str, InterfaceCounters] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def is_tunnel(name: str) -> bool:
    return bool(re.search(r"^(utun|tun|tap|wg|tailscale|zt)|vpn|wireguard|wintun", name, re.I))


def linux_routes(text: str, ipv6_text: str = "") -> list[RouteEntry]:
    candidates = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 8 or parts[1] != "00000000" or parts[7] != "00000000":
            continue
        try:
            flags = int(parts[3], 16)
            if flags & 1 and not flags & 0x200:  # RTF_UP, not RTF_REJECT
                gateway = socket.inet_ntoa(struct.pack("<I", int(parts[2], 16)))
                candidates.append((int(parts[6]), RouteEntry(gateway, parts[0], parts[3])))
        except ValueError:
            continue
    for line in ipv6_text.splitlines():
        parts = line.split()
        if len(parts) < 10 or parts[0] != "0" * 32 or parts[1] != "00":
            continue
        try:
            flags = int(parts[8], 16)
            if flags & 1 and not flags & 0x200:
                gateway = str(ipaddress.IPv6Address(int(parts[4], 16)))
                if gateway.startswith("fe80:"):
                    gateway += "%" + parts[9]
                # Prefer IPv4 for dual-stack monitoring; use IPv6 on IPv6-only hosts.
                candidates.append((1_000_000 + int(parts[5], 16), RouteEntry(gateway, parts[9], parts[8])))
        except ValueError:
            continue
    return [entry for _, entry in sorted(candidates, key=lambda pair: pair[0])]


def windows_state(text: str) -> tuple[list[RouteEntry], list[str]]:
    data = json.loads(text.lstrip("\ufeff"))
    routes = data.get("routes") or []
    if isinstance(routes, dict):
        routes = [routes]
    routes.sort(key=lambda route: (
        0 if route.get("DestinationPrefix") == "0.0.0.0/0" else 1,
        int(route.get("RouteMetric", 0)) + int(route.get("InterfaceMetric", 0)),
    ))
    result = []
    for route in routes:
        name = route.get("InterfaceAlias")
        gateway = route.get("NextHop")
        if name and gateway:
            if gateway.startswith("fe80:") and "%" not in gateway:
                gateway += "%" + str(route["InterfaceIndex"])
            description = str(route.get("Description", ""))
            result.append(RouteEntry(gateway, name, "T" if is_tunnel(name + " " + description) else "U"))
    dns = data.get("dns") or []
    return result, [dns] if isinstance(dns, str) else dns


WINDOWS_QUERY = r"""$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding
$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue)
$routes = @(Get-NetRoute -PolicyStore ActiveStore | Where-Object {
    $_.DestinationPrefix -in @('0.0.0.0/0', '::/0')
} | ForEach-Object {
    $route = $_
    $ipif = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily $route.AddressFamily
    $adapter = $adapters | Where-Object { $_.ifIndex -eq $route.InterfaceIndex } | Select-Object -First 1
    [pscustomobject]@{
        InterfaceAlias = $route.InterfaceAlias; InterfaceIndex = $route.InterfaceIndex
        DestinationPrefix = $route.DestinationPrefix; NextHop = $route.NextHop
        RouteMetric = $route.RouteMetric; InterfaceMetric = $ipif.InterfaceMetric
        Description = $adapter.InterfaceDescription
    }
})
$indexes = @($routes | Select-Object -ExpandProperty InterfaceIndex -Unique)
$dns = @(Get-DnsClientServerAddress | Where-Object { $_.InterfaceIndex -in $indexes } |
    ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
@{ routes = $routes; dns = $dns } | ConvertTo-Json -Depth 5 -Compress
"""


def collect_native() -> NativeState:
    system = platform.system()
    state = NativeState(system)
    try:
        addresses = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, entries in addresses.items():
            info = InterfaceInfo(name, "active" if stats.get(name) and stats[name].isup else "inactive")
            for address in entries:
                if address.family in (socket.AF_INET, socket.AF_INET6):
                    ip = ipaddress.ip_address(address.address.split("%")[0])
                    if ip.is_loopback or ip.is_link_local or ip.is_unspecified:
                        continue
                    (info.ipv4 if ip.version == 4 else info.ipv6).append(address.address)
                elif address.family == psutil.AF_LINK:
                    info.mac = address.address
            state.interfaces[name] = info
        state.counters = {name: InterfaceCounters(c.bytes_recv, c.bytes_sent, "psutil")
                          for name, c in psutil.net_io_counters(pernic=True).items()}
    except (OSError, psutil.Error, ValueError) as exc:
        state.warnings.append(f"Не удалось прочитать адаптеры: {exc}")

    if system == "Darwin":
        rc, text, error = run_command(["netstat", "-rn", "-f", "inet"])
        if rc:
            state.warnings.append(f"netstat: {error.strip() or 'не удалось получить маршруты'}")
        state.routes = parse_default_routes(text)
        rc, text, error = run_command(["route", "-n", "get", "default"])
        if rc:
            # IPv6-only networks use an IPv6 default route.
            rc, text, error = run_command(["route", "-n", "get", "-inet6", "default"])
        if not rc:
            gateway = re.search(r"gateway:\s*(\S+)", text)
            interface = re.search(r"interface:\s*(\S+)", text)
            if interface:
                active = RouteEntry(gateway[1] if gateway else "0.0.0.0", interface[1], "U")
                state.routes = [active] + [r for r in state.routes if r.netif != active.netif]
        rc, text, error = run_command(["scutil", "--dns"])
        if not rc:
            state.dns_servers = re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", text)
        else:
            state.warnings.append(f"scutil: {error.strip() or 'DNS-настройки недоступны'}")
    elif system == "Linux":
        try:
            ipv6_path = Path("/proc/net/ipv6_route")
            state.routes = linux_routes(Path("/proc/net/route").read_text(),
                                        ipv6_path.read_text() if ipv6_path.exists() else "")
        except OSError as exc:
            state.warnings.append(f"Таблица маршрутов: {exc}")
    elif system == "Windows":
        rc, text, error = run_command(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                                       "-Command", WINDOWS_QUERY], timeout=8)
        if rc:
            state.warnings.append(f"PowerShell: {error.strip() or 'маршруты и DNS недоступны'}")
        else:
            try:
                state.routes, state.dns_servers = windows_state(text)
            except (ValueError, TypeError, KeyError) as exc:
                state.warnings.append(f"Ответ PowerShell не распознан: {exc}")
    else:
        state.warnings.append(f"Системный сборщик для {system} не поддерживается.")
    if not state.dns_servers and system != "Windows":
        try:
            state.dns_servers = re.findall(r"^nameserver\s+(\S+)", Path("/etc/resolv.conf").read_text(), re.M)
        except OSError:
            pass
    state.dns_servers = list(dict.fromkeys(state.dns_servers))
    return state
