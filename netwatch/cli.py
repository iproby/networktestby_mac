from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import sqlite3
import subprocess
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
    p.add_argument("--quiet", action="store_true", help="Сохранять мониторинг без вывода каждого цикла (для фонового процесса)")
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
    p.add_argument("--no-log", action="store_true", help="Не сохранять JSONL и SQLite-историю")
    p.add_argument("--log-file", help="Совместимость: путь журнала; пустая строка отключает запись")
    p.add_argument("--speedtest", action="store_true", help="Выполнить разовый download-тест в текстовом/JSON-режиме")
    p.add_argument("--speedtest-url", help="URL download-теста, поддерживает {bytes}")
    p.add_argument("--speedtest-bytes", type=int, help="Лимит скачивания, байт")
    p.add_argument("--speedtest-timeout", type=float, help="Бюджет download-теста, секунд")
    p.add_argument("--profile", choices=["general", "calls", "gaming", "vpn", "economy"], help="Профиль задачи")
    p.add_argument("--notify", action="store_true", default=None, help="Локальные уведомления об устойчивом сбое/восстановлении")
    p.add_argument("--fixed-interval", action="store_true", help="Отключить адаптацию интервала")
    p.add_argument("--history", type=float, metavar="HOURS", help="Вывести сохранённые снимки за период")
    p.add_argument("--replay", type=Path, help="Открыть JSON-отчёт без сетевых операций")
    p.add_argument("--report", action="store_true", help="Один цикл и HTML/JSON-отчёт")
    p.add_argument("--raw-report", action="store_true", help="Экспортировать адреса без обезличивания")
    p.add_argument("--diagnose", choices=["quality", "trace", "http", "dns", "wifi", "processes", "dual", "mtu", "status", "agent"], help="Запустить отдельный диагностический инструмент")
    p.add_argument("--target", default="", help="Узел/URL выбранного инструмента")
    p.add_argument("--capture-label", help="Сохранить снимок до изменения VPN/сети")
    p.add_argument("--compare", type=Path, help="Сравнить текущий снимок с ранее сохранённым")
    p.add_argument("--background", choices=["start", "status", "stop"], help="Управление фоновым процессом пользователя")
    p.add_argument("--service", choices=["install", "start", "status", "stop", "remove"], help="Явная регистрация/управление запуском при входе пользователя")
    p.add_argument("--agent", action="store_true", help="Запустить вторую точку наблюдения и сервер ограниченных тестов")
    p.add_argument("--bind", default="127.0.0.1", help="Адрес сервера агента")
    p.add_argument("--port", type=int, default=8765, help="Порт агента")
    p.add_argument("--udp-port", type=int, help="Включить UDP-отражатель на указанном порту")
    p.add_argument("--tls-cert", type=Path, help="TLS-сертификат агента в PEM")
    p.add_argument("--tls-key", type=Path, help="TLS-ключ агента в PEM")
    return p


def resolve(args) -> Settings:
    cfg = Settings.load(args.config) if args.config else Settings()
    if args.profile:
        cfg = cfg.preset(args.profile)
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
    if args.notify is not None:
        cfg.notifications = args.notify
    if args.fixed_interval:
        cfg.adaptive = False
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
        if args.replay and (args.agent or args.diagnose or args.background or args.service or args.speedtest or
                            args.capture_label or args.compare or args.report or args.history is not None):
            raise ValueError("--replay несовместим с сетевыми/фоновыми командами")
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
        directory = (args.state_dir or state_directory()).expanduser()
        if args.background or args.service:
            from . import background
            result = (background.manage(args.background, directory, cfg) if args.background else
                      background.service(args.service, directory, cfg))
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return result.get("exit_code", 0)
        journal = Journal(directory, not args.no_log and args.log_file != "" and not args.replay)
        if args.log_file:
            journal.path = Path(args.log_file).expanduser()
        monitor = Monitor(cfg, journal)
        if args.history is not None:
            import math
            from datetime import datetime, timedelta, timezone
            if not math.isfinite(args.history) or not 0 < args.history <= 720:
                raise ValueError("Период истории: от 0 до 720 часов")
            since = (datetime.now(timezone.utc) - timedelta(hours=args.history)).isoformat()
            data = journal.history.query(since=since, limit=10000)
            if args.json:
                print(json.dumps(data, ensure_ascii=False))
            else:
                print(f"Снимков в периоде: {len(data)} (до 10000 последних)")
                for event in data:
                    s = event["snapshot"]
                    print(s["timestamp"], s["cause"]["status"], s["cause"]["summary"])
            return 0
        if args.replay:
            from .reports import load_report
            monitor.load_offline(load_report(args.replay))
            if args.plain or args.json or not (sys.stdin.isatty() and sys.stdout.isatty()):
                for snapshot in monitor.history:
                    print(json.dumps(asdict(snapshot), ensure_ascii=False) if args.json else plain_summary(snapshot))
                return 0
        if args.agent:
            from .agent import serve
            if not 0 <= args.port <= 65535 or args.udp_port is not None and not 0 <= args.udp_port <= 65535:
                raise ValueError("Некорректный порт агента")
            serve(monitor, args.bind, args.port, args.udp_port, args.tls_cert, args.tls_key)
            return 0
        if args.diagnose:
            from .tools import run
            result = run(monitor, args.diagnose, args.target)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            if args.report:
                print(str(monitor.export(not args.raw_report)), file=sys.stderr)
            return 0
        if not (args.once or args.plain or args.json or args.report or args.capture_label or args.compare) and sys.stdin.isatty() and sys.stdout.isatty():
            from .tui import NetWatchApp
            NetWatchApp(monitor).run()
            return 0
        stop = threading.Event()
        previous_handlers = {}
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, lambda *_: stop.set())
        try:
            last_warning = None
            while not stop.is_set():
                snapshot = monitor.sample()
                if args.speedtest:
                    monitor.speed_result = monitor.measure_speed()
                    snapshot.performance.cloudflare_speed = monitor.speed_result
                monitor.accept(snapshot)
                if args.capture_label:
                    from uuid import uuid4
                    directory.mkdir(parents=True, exist_ok=True)
                    capture = directory / f"capture-{uuid4().hex[:8]}.json"
                    capture.write_text(json.dumps({"label": args.capture_label, "snapshot": asdict(snapshot)}, ensure_ascii=False, indent=2), encoding="utf-8")
                    print(f"Снимок сохранён: {capture}", file=sys.stderr)
                if args.compare:
                    from .insights import compare
                    before = json.loads(args.compare.read_text(encoding="utf-8"))
                    comparison = monitor.record_diagnostic("comparison", compare(before.get("snapshot", before), asdict(snapshot)))
                    print(json.dumps(comparison, ensure_ascii=False), file=sys.stderr)
                if args.report:
                    print(f"Отчёт: {monitor.export(not args.raw_report)}", file=sys.stderr)
                if not args.quiet:
                    print(json.dumps(asdict(snapshot), ensure_ascii=False) if args.json else plain_summary(snapshot), flush=True)
                if monitor.storage_warning and monitor.storage_warning != last_warning:
                    print(monitor.storage_warning, file=sys.stderr)
                last_warning = monitor.storage_warning
                if args.once or args.report or args.capture_label or args.compare:
                    break
                stop.wait(monitor.next_interval())
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        return 0
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError, argparse.ArgumentTypeError) as exc:
        print(f"NetWatch: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
