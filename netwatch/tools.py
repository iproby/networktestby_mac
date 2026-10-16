from dataclasses import asdict
from urllib.parse import urlsplit

from . import measurements as m
from .agent import read_agent
from .core import iso_now
from .insights import compare
from .system import process_activity, wifi

TOOLS = {"quality": "Качество под нагрузкой", "trace": "Маршрут / MTR", "http": "HTTP / TLS",
         "dns": "DNS / DoH", "wifi": "Wi-Fi", "processes": "Процессы", "dual": "IPv4 / IPv6",
         "mtu": "MTU / DF", "status": "Статусы провайдеров", "agent": "Вторая точка наблюдения"}


def run(monitor, tool, target=""):
    if monitor.offline:
        raise ValueError("Офлайн-режим: сетевые и системные измерения отключены")
    cfg = monitor.settings
    if tool == "quality":
        result = m.quality(monitor)
    elif tool == "trace":
        result = m.trace(target or "1.1.1.1", min(cfg.timeout, 1))
    elif tool == "http":
        url = target or (cfg.http_urls[0] if cfg.http_urls else "")
        with monitor.budget.reserve(65536) as meter:
            result = {"http": m.http_details(url, cfg.timeout), "certificate": m.certificate(url, cfg.timeout)}
            meter.update(bytes=result["http"].get("bytes", result["http"].get("probe", {}).get("bytes_read", 0)), requests=2)
    elif tool == "dns":
        name = urlsplit(target).hostname if "://" in target else target or (cfg.dns_names[0] if cfg.dns_names else "")
        name = m.target_host(name)
        result = m.dns_compare(name, cfg.dns_servers, cfg.doh_url, cfg.timeout)
    elif tool == "wifi":
        result = wifi(cfg.interface)
    elif tool == "processes":
        result = process_activity()
    elif tool == "dual":
        with monitor.budget.reserve(131072) as meter:
            result = m.dual_stack(target or (cfg.http_urls[0] if cfg.http_urls else ""), cfg.timeout)
            meter.update(bytes=sum(result[k].get("bytes", result[k].get("probe", {}).get("bytes_read", 0)) for k in ("ipv4", "ipv6")), requests=2)
    elif tool == "mtu":
        result = m.mtu_probe(target or "1.1.1.1", cfg.timeout)
    elif tool == "status":
        result = m.status_feeds(cfg.status_feeds, cfg.timeout)
    elif tool == "agent":
        result = read_agent(target or cfg.remote_agent_url or "http://127.0.0.1:8765", cfg.timeout)
        if monitor.history:
            result["comparison"] = compare(asdict(monitor.history[-1]), result["snapshot"])
    else:
        raise ValueError("Неизвестный инструмент")
    return monitor.record_diagnostic(tool, result)
