from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .engine import Monitor
from .settings import Settings
from .storage import Journal, state_directory


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="NetWatch — диагностика сети для macOS, Windows и Linux")
    p.add_argument("--version", action="version", version=f"NetWatch {__version__}")
    p.add_argument("--config", type=Path, help="JSON-профиль контрольных точек")
    p.add_argument("--write-config", type=Path, help="Сохранить профиль и завершиться; существующий файл не перезаписывается")
    p.add_argument("--once", action="store_true", help="Один цикл без полноэкранного интерфейса")
    p.add_argument("--plain", action="store_true", help="Текстовый мониторинг")
    p.add_argument("--json", action="store_true", help="Только JSON: один snapshot на строку")
    p.add_argument("--interval", type=float, help="Пауза между циклами, секунд")
    p.add_argument("--timeout", type=float, help="Таймаут отдельной проверки, секунд")
    p.add_argument("--dns-name", action="append", help="Контрольное DNS-имя; можно повторять")
    p.add_argument("--dns-server", action="append", help="IP сервера прямого DNS; можно повторять")
    p.add_argument("--no-direct-dns", action="store_true", help="Не проверять прямой UDP DNS")
    p.add_argument("--public-endpoint", action="append", help="IP:порт[,порт], IPv6 — [адрес]:порт")
    p.add_argument("--http-url", action="append", help="Контрольный HTTP(S)-URL; можно повторять")
    p.add_argument("--regional-service", action="append", help="CODE|Регион|Имя|URL")
    p.add_argument("--no-regions", action="store_true", help="Отключить региональные проверки")
    p.add_argument("--interface", help="Адаптер для счётчиков; запросы идут по системному маршруту")
    p.add_argument("--list-interfaces", action="store_true", help="Показать адаптеры и завершиться")
    p.add_argument("--state-dir", type=Path, help="Каталог журналов и отчётов")
    p.add_argument("--no-log", action="store_true", help="Не сохранять JSONL-журнал")
    p.add_argument("--log-file", help="Совместимость: путь журнала; пустая строка отключает запись")
    p.add_argument("--speedtest", action="store_true", help="Выполнить разовый download-тест в текстовом/JSON-режиме")
    p.add_argument("--speedtest-url", help="URL download-теста, поддерживает {bytes}")
    p.add_argument("--speedtest-bytes", type=int, help="Лимит скачивания, байт")
    p.add_argument("--speedtest-timeout", type=float, help="Бюджет download-теста, секунд")
    return p


def resolve(args) -> Settings:
    cfg = Settings.load(args.config) if args.config else Settings()
    for name in ("interval", "timeout", "interface", "speedtest_url", "speedtest_bytes", "speedtest_timeout"):
        value = getattr(args, name)
        if value is not None:
            setattr(cfg, name, value)
    for argument, field in (("dns_name", "dns_names"), ("dns_server", "dns_servers"),
                            ("public_endpoint", "public_endpoints"), ("http_url", "http_urls")):
        if getattr(args, argument) is not None:
            setattr(cfg, field, getattr(args, argument))
    if args.regional_service:
        cfg.regional_services = [item.split("|", 3) for item in args.regional_service]
    if args.no_regions:
        cfg.regional_services = []
    if args.no_direct_dns:
        cfg.dns_servers = []
    return cfg.validate()


def plain_summary(s) -> str:
    labels = {"ok": "OK", "degraded": "ВНИМАНИЕ", "down": "СБОЙ"}
    lines = [f"\n{s.timestamp}  {labels[s.cause.status]}  {s.cause.summary}"]
    if s.interface:
        lines.append(f"  {s.platform} · {s.interface.name} · {', '.join(s.interface.ipv4 + s.interface.ipv6)}")
    for label, probes, attribute in (("TCP", s.public_probes, "reachable"), ("DNS", s.system_dns, "ok"),
                                      ("Direct DNS", s.direct_dns, "ok"), ("HTTP", s.http_probes, "ok"),
                                      ("Регионы", s.regional_services, "ok")):
        lines.append(f"  {label}: {sum(bool(getattr(p, attribute)) for p in probes)}/{len(probes)}" if probes else f"  {label}: отключено")
    lines.extend("  Почему: " + item for item in s.cause.evidence)
    lines.extend("  → " + item for item in s.cause.next_steps)
    if s.performance and s.performance.cloudflare_speed:
        speed = s.performance.cloudflare_speed
        lines.append(f"  Download {speed.provider}: {speed.download_mbps} Мбит/с" if speed.ok else f"  Download: {speed.error}")
    return "\n".join(lines)


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    p = parser()
    args = p.parse_args(argv)
    try:
        cfg = resolve(args)
        if args.write_config:
            cfg.save(args.write_config)
            print(f"Профиль сохранён: {args.write_config}")
            return 0
        if args.list_interfaces:
            from .native import collect_native
            native = collect_native()
            for info in native.interfaces.values():
                print(f"{info.name}\t{info.status}\t{', '.join(info.ipv4 + info.ipv6) or '—'}")
            for warning in native.warnings:
                print(warning, file=sys.stderr)
            return 0
        journal = Journal(args.state_dir or state_directory(), not args.no_log and args.log_file != "")
        if args.log_file:
            journal.path = Path(args.log_file).expanduser()
        monitor = Monitor(cfg, journal)
        if not (args.once or args.plain or args.json) and sys.stdin.isatty() and sys.stdout.isatty():
            from .tui import NetWatchApp
            NetWatchApp(monitor).run()
            return 0
        stop = threading.Event()
        previous_handlers = {}
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, lambda *_: stop.set())
        try:
            while not stop.is_set():
                snapshot = monitor.sample()
                if args.speedtest:
                    monitor.speed_result = monitor.measure_speed()
                    snapshot.performance.cloudflare_speed = monitor.speed_result
                monitor.accept(snapshot)
                print(json.dumps(asdict(snapshot), ensure_ascii=False) if args.json else plain_summary(snapshot), flush=True)
                if monitor.storage_warning:
                    print(monitor.storage_warning, file=sys.stderr)
                if args.once:
                    break
                stop.wait(cfg.interval)
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        return 0
    except (OSError, ValueError, argparse.ArgumentTypeError) as exc:
        print(f"NetWatch: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
