"""Bounded, explicit diagnostics. Probes report their actual transport and scope."""
from __future__ import annotations

import ipaddress
import json
import math
import re
import shutil
import socket
import ssl
import statistics
import struct
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlsplit

from . import core
from .trust import https_context


def target_host(value):
    host = urlsplit(value).hostname if "://" in value else value.strip("[]")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if not host or len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p) for p in host.split(".")):
            raise ValueError("Укажите IP-адрес, имя узла или HTTP(S)-URL")
        return host


def percentile(values, quantile):
    if not values:
        return None
    values = sorted(values)
    position = (len(values) - 1) * quantile
    low, high = math.floor(position), math.ceil(position)
    return round(values[low] + (values[high] - values[low]) * (position - low), 2)


def latency_stats(points, attempts):
    return {"samples": len(points), "attempts": attempts, "failed_connections": attempts - len(points),
            "tcp_failure_percent": round((attempts - len(points)) / attempts * 100, 1) if attempts else None,
            "median_ms": percentile(points, .5), "p95_ms": percentile(points, .95),
            "jitter_ms": round(statistics.mean(abs(b - a) for a, b in zip(points, points[1:])), 2) if len(points) > 1 else None,
            "points_ms": points, "transport": "TCP handshake; failure rate is not packet loss"}


def pulse(host, port, timeout):
    result = core.tcp_probe(host, [port], timeout)
    return result.latency_ms if result.outcome == "connected" else None


def upload(url, count, timeout, opener=None):
    body = b"N" * count
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/octet-stream", "User-Agent": "NetWatch/4"}, method="POST")
    started = time.monotonic()
    try:
        with (opener.open(request, timeout=timeout) if opener else urllib.request.urlopen(request, timeout=timeout, context=https_context())) as response:
            response.read(1024)
            elapsed = max(.001, time.monotonic() - started)
            return {"ok": 200 <= response.status < 400, "mbps": round(count * 8 / elapsed / 1_000_000, 2),
                    "bytes": count, "accounted_bytes": count, "duration_s": elapsed, "status_code": response.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "accounted_bytes": count,
                "note": "Бюджет консервативно учитывает попытку отправки целиком; фактическая отправка не подтверждена"}


def quality(monitor):
    cfg = monitor.settings
    if not cfg.public_endpoints:
        raise ValueError("Для теста нужен контрольный IP:порт в public_endpoints")
    _, host, ports = core.parse_public_endpoints(cfg.public_endpoints)[0]
    port = ports[0]
    attempts, points = 0, []
    deadline = time.monotonic() + min(30, cfg.speedtest_timeout * 2)
    for _ in range(cfg.quality_samples):
        if time.monotonic() >= deadline:
            break
        value = pulse(host, port, cfg.timeout)
        attempts += 1
        if value is not None:
            points.append(value)
    result = {"target": f"{host}:{port}", "idle": latency_stats(points, attempts), "stages": {}}
    from .agent import bulk_opener
    with monitor.budget.reserve(cfg.speedtest_bytes * 2) as meter:
        for direction in ("download", "upload"):
            points, attempts = [], 0
            with ThreadPoolExecutor(max_workers=1) as executor:
                if direction == "download":
                    future = executor.submit(core.measure_download_speed,
                        core.build_speedtest_url(cfg.speedtest_url, cfg.speedtest_bytes), cfg.speedtest_timeout, cfg.speedtest_bytes,
                        bulk_opener(cfg.speedtest_url, cfg.remote_agent_url))
                else:
                    future = executor.submit(upload, cfg.upload_url, cfg.speedtest_bytes, cfg.speedtest_timeout,
                                             bulk_opener(cfg.upload_url, cfg.remote_agent_url))
                while not future.done() and attempts < 100:
                    value = pulse(host, port, min(cfg.timeout, .5))
                    attempts += 1
                    if value is not None:
                        points.append(value)
                    time.sleep(.02)
                measured = future.result()
            data = asdict(measured) if direction == "download" else measured
            meter["bytes"] += data.get("transferred_bytes", data.get("accounted_bytes", 0))
            meter["requests"] += attempts + 1
            result["stages"][direction] = {"transfer": data, "loaded": latency_stats(points, attempts)}
    idle = result["idle"]["median_ms"]
    for stage in result["stages"].values():
        loaded = stage["loaded"]["median_ms"]
        stage["latency_increase_ms"] = round(loaded - idle, 2) if loaded is not None and idle is not None else None
    if cfg.udp_endpoint:
        from .agent import udp_measure
        result["udp"] = udp_measure(cfg.udp_endpoint, cfg.quality_samples, min(cfg.timeout, 1))
    else:
        result["udp"] = {"status": "unconfigured", "reason": "Настройте udp_endpoint своего NetWatch-агента для измерения потерь UDP"}
    stats = result["idle"]
    observed = [stats] + [s["loaded"] for s in result["stages"].values()]
    worst = max((s["p95_ms"] for s in observed if s["p95_ms"] is not None), default=None)
    attention = ((worst is not None and worst > (80 if cfg.profile == "gaming" else 150)) or
                 any(s["failed_connections"] for s in observed) or any(not s["transfer"]["ok"] for s in result["stages"].values()))
    insufficient = any(s["samples"] < 3 for s in observed)
    result["scenario"] = {"profile": cfg.profile, "worst_p95_ms": worst,
                          "status": "attention" if attention else "insufficient_data" if insufficient else "measured_conditions_ok",
                          "note": "Предварительная оценка контрольного TCP-пути; реальная телеметрия звонка/игры не собрана"}
    return result


def http_details(url, timeout=5, family=None):
    from .settings import Settings
    Settings(http_urls=[url]).validate()
    curl = shutil.which("curl.exe" if __import__("os").name == "nt" else "curl")
    if not curl:
        return {"status": "limited", "probe": asdict(core.http_probe(url, timeout)), "reason": "Для разложения времени нужен curl"}
    names = ("http_code", "url_effective", "num_redirects", "time_namelookup", "time_connect", "time_appconnect", "time_starttransfer", "time_total", "size_download")
    output_format = "\n".join("%{" + name + "}" for name in names)
    with tempfile.TemporaryDirectory(prefix="netwatch-http-") as temporary:
        body = Path(temporary) / "body"
        command = [curl, "--silent", "--show-error", "--location", "--max-redirs", "5", "--max-time", str(timeout),
                   "--connect-timeout", str(timeout), "--max-filesize", "65536", "--range", "0-65535",
                   "--output", str(body), "--write-out", output_format, "--proto", "=http,https", "--proto-redir", "=http,https"]
        if family:
            command += ["--ipv4" if family == 4 else "--ipv6"]
        command += ["--url", url]
        rc, stdout, stderr = core.run_command(command, timeout=timeout + 2)
        fields = dict(zip(names, stdout.splitlines()))
        def number(name):
            try:
                return float(fields.get(name, "0"))
            except ValueError:
                return 0
        dns, tcp, tls, first = (number(key) for key in ("time_namelookup", "time_connect", "time_appconnect", "time_starttransfer"))
        result = {"url": url, "final_url": fields.get("url_effective"), "status_code": int(number("http_code")),
                  "redirects": int(number("num_redirects")), "family_requested": family,
                  "timing_ms": {"dns": round(dns * 1000, 2), "tcp": round(max(0, tcp - dns) * 1000, 2),
                      "tls": round(max(0, tls - tcp) * 1000, 2) if tls else None,
                      "wait_first_byte": round(max(0, first - (tls or tcp)) * 1000, 2), "total": round(number("time_total") * 1000, 2)},
                  "bytes": int(number("size_download")), "bounded_body": True, "exit_code": rc,
                  "ok": rc in (0, 63) and 200 <= number("http_code") < 400, "error": stderr.strip() or None,
                  "note": "HTTP через настроенный прокси; времена перенаправлений/прокси могут включать несколько соединений"}
        return result


def certificate(url, timeout=3):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return {"status": "unavailable", "reason": "Нужен HTTPS URL"}
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=timeout) as transport:
            with https_context().wrap_socket(transport, server_hostname=parsed.hostname) as secure:
                cert = secure.getpeercert()
                return {"status": "ok", "issuer": cert.get("issuer"), "subject": cert.get("subject"), "not_after": cert.get("notAfter"),
                        "days_left": round((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400, 1),
                        "scope": "direct TLS with certificate verification; may differ from HTTP proxy path"}
    except (OSError, ssl.SSLError) as exc:
        return {"status": "failed", "error": str(exc), "scope": "direct TLS"}


def dns_compare(name, servers, doh_url, timeout=2):
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.rcode
    rows = []
    system = core.system_dns_lookup(name, timeout)
    ok, addresses = core.run_with_timeout(lambda: socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM), timeout)
    rows.append({"transport": "system", "ok": system.ok, "latency_ms": system.latency_ms,
                 "answers": sorted({a[4][0] for a in addresses}) if ok else [], "error": system.error})
    for kind in ("A", "AAAA"):
        query = dns.message.make_query(name, kind)
        for server in list(servers) + [doh_url]:
            started = time.monotonic()
            try:
                if server == doh_url:
                    request = urllib.request.Request(server, data=query.to_wire(), headers={"Content-Type": "application/dns-message", "Accept": "application/dns-message"})
                    with urllib.request.urlopen(request, timeout=timeout, context=https_context()) as response:
                        answer = dns.message.from_wire(response.read(65536))
                else:
                    answer = dns.query.udp(query, server, timeout=timeout)
                    if answer.flags & 0x0200:
                        answer = dns.query.tcp(query, server, timeout=timeout)
                if not query.is_response(answer):
                    raise ValueError("DNS response does not match question/transaction")
                rows.append({"transport": "DoH" if server == doh_url else "UDP/TCP", "server": server, "type": kind,
                             "ok": answer.rcode() == 0, "rcode": dns.rcode.to_text(answer.rcode()),
                             "answers": [r.to_text() for rr in answer.answer for r in rr],
                             "latency_ms": round((time.monotonic() - started) * 1000, 1)})
            except Exception as exc:
                rows.append({"server": server, "type": kind, "ok": False, "error": str(exc)})
    return {"name": name, "results": rows, "note": "Разные ответы могут быть корректны для split DNS/CDN; расхождение само по себе не доказывает подмену"}


def udp_trace_linux(host, timeout=.5, hops=12, repeats=2):
    ok, destination = core.run_with_timeout(lambda: socket.gethostbyname(host), max(.1, min(timeout, 1)))
    if not ok:
        raise OSError("Не удалось разрешить узел трассировки: " + str(destination))
    rows = []
    deadline = time.monotonic() + 20
    for ttl in range(1, hops + 1):
        points, addresses, reached, sent = [], set(), False, 0
        for attempt in range(repeats):
            if time.monotonic() >= deadline:
                break
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as transport:
                transport.setsockopt(socket.SOL_IP, 11, 1)  # Linux IP_RECVERR: unprivileged ICMP error queue.
                transport.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                transport.setblocking(False)
                transport.connect((destination, 33434 + ttl))
                started = time.monotonic()
                sent += 1
                transport.send(b"NetWatch route probe")
                import select
                readable, _, errors = select.select([transport], [], [transport], min(timeout, max(.001, deadline - started)))
                if not (readable or errors):
                    continue
                try:
                    _, controls, _, _ = transport.recvmsg(512, 512, socket.MSG_ERRQUEUE)
                    for level, kind, detail in controls:
                        if level == socket.SOL_IP and kind == 11 and len(detail) >= 24:
                            _, origin, icmp_type, code, _, _, _ = struct.unpack("=IBBBBII", detail[:16])
                            if origin == 2:
                                offender = socket.inet_ntoa(detail[20:24])
                                addresses.add(offender)
                                points.append(round((time.monotonic() - started) * 1000, 2))
                                reached = reached or (icmp_type == 3 and code == 3 and offender == destination)
                except (BlockingIOError, ConnectionRefusedError):
                    pass
        rows.append({"hop": ttl, "addresses": sorted(addresses), "latencies_ms": points, "responded": len(points),
                     "attempts": sent, "reached": reached, "median_ms": percentile(points, .5)})
        if reached or time.monotonic() >= deadline:
            break
    return {"method": "UDP TTL / Linux error queue", "target": destination, "hops": rows,
            "note": "Доля ответов узла не является потерями транзитных пакетов; * означает отсутствие ответа на пробу"}


def trace(host, timeout=.5):
    host = target_host(host)
    import platform
    system = platform.system()
    if system == "Linux" and ":" not in host:
        try:
            return udp_trace_linux(host, min(timeout, 1))
        except OSError as exc:
            fallback = str(exc)
    else:
        fallback = "Для этой платформы/семейства используется системная трассировка"
    executable = shutil.which("tracert" if system == "Windows" else "traceroute6" if ":" in host else "traceroute")
    if not executable:
        return {"status": "unavailable", "reason": fallback + "; системная утилита отсутствует"}
    args = [executable, "-d", "-h", "12", "-w", str(int(timeout * 1000)), host] if system == "Windows" else [executable, "-n", "-m", "12", "-q", "2", "-w", str(max(1, timeout)), host]
    rc, text, error = core.run_command(args, timeout=25, encoding="oem" if system == "Windows" else "utf-8")
    return {"target": host, "method": Path(executable).name, "exit_code": rc, "output": text, "error": error or None,
            "hops": parse_trace(text, 3 if system == "Windows" else 2),
            "note": "Отсутствие ответа промежуточного узла не доказывает потерю транзитного трафика"}


def parse_trace(text, attempts):
    rows = []
    for line in text.splitlines():
        match = re.match(r"\s*(\d+)\s+(.+)", line)
        if not match:
            continue
        addresses = []
        for word in match[2].split():
            try:
                address = str(ipaddress.ip_address(word.strip("[]()")))
                if address not in addresses:
                    addresses.append(address)
            except ValueError:
                pass
        points = [float(value) for value in re.findall(r"<?\s*(\d+(?:\.\d+)?)\s*(?:ms|мс)\b", match[2], re.IGNORECASE)]
        rows.append({"hop": int(match[1]), "addresses": addresses, "latencies_ms": points, "responded": len(points),
                     "attempts": attempts, "median_ms": percentile(points, .5)})
    return rows


class MTRSession:
    """Repeated bounded traces. RTT window is bounded; response counts are cumulative."""
    def __init__(self):
        self.rows, self.rounds = {}, 0

    def update(self, result):
        self.rounds += 1
        for hop in result.get("hops", []):
            row = self.rows.setdefault(hop["hop"], {"hop": hop["hop"], "addresses": set(), "latencies_ms": [],
                                                   "attempts": 0, "responded": 0})
            row["addresses"].update(hop["addresses"])
            row["latencies_ms"] = (row["latencies_ms"] + hop["latencies_ms"])[-1000:]
            row["attempts"] += hop["attempts"]
            row["responded"] += hop["responded"]
            row["last_round"] = self.rounds
        hops = []
        for _, row in sorted(self.rows.items()):
            points = row["latencies_ms"]
            hops.append({**row, "addresses": sorted(row["addresses"]), "median_ms": percentile(points, .5),
                         "p95_ms": percentile(points, .95), "average_ms": round(statistics.mean(points), 2) if points else None})
        return {"target": result.get("target", ""), "method": "MTR / repeated " + result.get("method", "trace"),
                "rounds": self.rounds, "hops": hops,
                "note": "Ответы/пробы — за сеанс; RTT — последние 1000 ответов каждого TTL. Адреса могут меняться. <1 мс показано верхней границей 1 мс. Молчание узла не доказывает транзитные потери."}


def dual_stack(url, timeout=3):
    return {"ipv4": http_details(url, timeout, 4), "ipv6": http_details(url, timeout, 6),
            "note": "При HTTP-прокси флаг семейства может относиться к соединению с прокси, а не с сервером"}


def mtu_probe(host, timeout=2):
    host = target_host(host)
    if ":" in host:
        return {"status": "unavailable", "reason": "Этот эксперимент проверяет IPv4 DF; для IPv6 нужен отдельный PMTU-сборщик"}
    ping = shutil.which("ping")
    if not ping:
        return {"status": "unavailable", "reason": "Нет системного ping или разрешения ICMP"}
    import platform
    system = platform.system()
    rows = []
    for payload in (1200, 1372, 1472):
        args = [ping, "-n", "1", "-f", "-l", str(payload), "-w", str(int(timeout * 1000)), host] if system == "Windows" else (
            [ping, "-n", "-c", "1", "-D", "-s", str(payload), host] if system == "Darwin" else
            [ping, "-n", "-c", "1", "-M", "do", "-s", str(payload), host])
        rc, output, error = core.run_command(args, timeout=timeout + 1)
        rows.append({"ipv4_packet_bytes": payload + 28, "reply": rc == 0, "output": (output + error)[-1000:]})
    return {"target": host, "results": rows, "note": "Неуспех может означать фильтрацию ICMP; это не точное измерение PMTU"}


def status_feeds(feeds, timeout=2):
    result = []
    for name, url in feeds.items():
        try:
            with urllib.request.urlopen(url, timeout=timeout, context=https_context()) as response:
                data = json.loads(response.read(200000))
            result.append({"provider": name, "source": url, "status": data.get("status", {}), "observed_at": core.iso_now()})
        except Exception as exc:
            result.append({"provider": name, "source": url, "error": str(exc)})
    return {"providers": result, "note": "Публичный статус — внешний контекст, не доказательство причины локального сбоя"}
