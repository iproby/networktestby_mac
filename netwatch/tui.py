"""Responsive Textual dashboard. Every number comes from the current session."""
from __future__ import annotations

import asyncio
import statistics
import time
from dataclasses import asdict
from datetime import datetime

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (Button, Checkbox, DataTable, Footer, Header, Input,
                             Label, Sparkline, Static, TabbedContent, TabPane)

from .core import Snapshot, format_latency, format_mbps, iso_now
from .engine import Monitor, incident_duration

STATUS = {"ok": ("СЕТЬ ДОСТУПНА", "#62e2ba"), "degraded": ("ЕСТЬ ЗАМЕЧАНИЯ", "#ffc875"),
          "down": ("СВЯЗЬ НАРУШЕНА", "#ff7e92")}


def clock(value: str) -> str:
    return datetime.fromisoformat(value).astimezone().strftime("%H:%M:%S")


def duration(seconds: float) -> str:
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}"


def probe_rows(s: Snapshot) -> list[dict]:
    rows = []
    if s.gateway_probe:
        p = s.gateway_probe
        rows.append(dict(kind="Шлюз", target=p.target, ok=p.reachable, latency=p.latency_ms,
                         detail=p.detail, data=asdict(p)))
    for p in s.public_probes:
        rows.append(dict(kind="TCP", target=p.target, ok=p.reachable, latency=p.latency_ms,
                         detail=p.outcome, data=asdict(p)))
    for kind, probes in (("DNS системы", s.system_dns), ("DNS прямой", s.direct_dns)):
        for p in probes:
            rows.append(dict(kind=kind, target=f"{p.name} → {p.server}", ok=p.ok, latency=p.latency_ms,
                             detail=p.error or f"Ответов: {p.answer_count}", data=asdict(p)))
    for p in s.http_probes:
        rows.append(dict(kind="HTTP(S)", target=p.url, ok=p.ok, latency=p.latency_ms,
                         detail=p.error or f"HTTP {p.status_code}", data=asdict(p)))
    for p in s.regional_services:
        rows.append(dict(kind=p.region, target=f"{p.name} · {p.url}", ok=p.ok, latency=p.latency_ms,
                         detail=p.error or f"HTTP {p.status_code}", data=asdict(p)))
    return rows


class Metric(Vertical):
    def __init__(self, title: str, identity: str):
        super().__init__(id=identity, classes="metric")
        self.caption = title

    def compose(self) -> ComposeResult:
        yield Static(self.caption, classes="metric-label", markup=False)
        yield Static("—", classes="metric-value", markup=False)
        yield Static("Ожидание первого цикла", classes="metric-note", markup=False)

    def show(self, value, note: str) -> None:
        self.query_one(".metric-value", Static).update(value)
        self.query_one(".metric-note", Static).update(note)


class Help(ModalScreen):
    BINDINGS = [("escape", "dismiss", "Закрыть"), ("question_mark", "dismiss", "Закрыть")]

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help-dialog"):
            yield Static("NETWATCH / КАК ЧИТАТЬ МОНИТОР", classes="section-title")
            yield Static(
                "1–5  Переключение вкладок\n"
                "R     Проверить сейчас\n"
                "P     Пауза / продолжить\n"
                "S     Замерить download (по умолчанию до 5 МБ)\n"
                "E     Экспортировать JSON-отчёт\n"
                "Q     Завершить мониторинг\n"
                "Tab   Перейти к следующему элементу\n"
                "↑ ↓   Выбрать проверку; Enter — подробности\n\n"
                "Задержка — медиана успешных TCP-соединений с контрольными IP. "
                "Она отличается от ping. Джиттер — средняя разница соседних значений этой медианы.\n\n"
                "Доля OK относится только к выполненным циклам этой сессии; паузы не считаются. "
                "Пропущенные и отключённые проверки не превращаются в нули.\n\n"
                "Регион обозначает принадлежность сервиса, а не местоположение его сервера. "
                "Ответы 403/429 могут означать ограничение сайта. Диагноз — гипотеза с основаниями.\n\n"
                "HTTPS проверяется с системным доверием сертификатам. Права администратора не нужны. "
                "Отчёт и журнал содержат IP-адреса и имена адаптеров: просмотрите их перед отправкой.",
                markup=False,
            )
            yield Button("Понятно", id="close-help", variant="primary")

    @on(Button.Pressed, "#close-help")
    def close_help(self) -> None:
        self.dismiss()


class NetWatchApp(App):
    TITLE = "NETWATCH"
    SUB_TITLE = "Сеть под наблюдением"
    ENABLE_COMMAND_PALETTE = False
    CSS = """
    Screen { background: #090f18; color: #d7e4f0; }
    Header { background: #132235; color: #78d8f5; height: 3; }
    HeaderIcon { display: none; }
    Footer { background: #132235; }
    #session { height: 2; padding: 0 2; color: #8fa8be; content-align: left middle; }
    #metrics { height: 6; grid-size: 4; grid-columns: 1fr 1fr 1fr 1fr; grid-gutter: 1; margin: 0 1; }
    .metric { background: #111e2d; border-left: thick #34516b; padding: 0 1; height: 5; }
    .metric-label { color: #8fa8be; height: 1; }
    .metric-value { color: #eaf6ff; text-style: bold; height: 2; content-align: left middle; }
    .metric-note { color: #8fa8be; height: 1; }
    .metric.ok { border-left: thick #62e2ba; }
    .metric.degraded { border-left: thick #ffc875; }
    .metric.down { border-left: thick #ff7e92; }
    TabbedContent { height: 1fr; }
    Tabs { background: #111e2d; }
    Tab { padding: 0 2; }
    TabPane { padding: 1; }
    .panel { background: #0f1a28; border: round #2b4056; padding: 1 2; margin-bottom: 1; height: auto; }
    .section-title { color: #78d8f5; text-style: bold; margin-bottom: 1; height: auto; }
    #overview-row { height: auto; }
    #diagnosis-panel { width: 2fr; height: auto; min-height: 15; margin-right: 1; }
    #chain-panel { width: 1fr; height: 15; padding: 0 1; }
    #diagnosis, #evidence, #next-step, #network, #settings-note { height: auto; }
    #diagnosis { text-style: bold; margin-bottom: 1; }
    #evidence { color: #a9bfd2; margin-bottom: 1; }
    #next-step { color: #62e2ba; }
    #chain { height: 11; }
    #latency-chart { height: 3; color: #78d8f5; background: #0f1a28; }
    #latency-caption { height: auto; color: #8fa8be; }
    #speed { height: auto; margin-top: 1; color: #a9bfd2; }
    #probe-toolbar { height: 3; margin-bottom: 1; }
    #filter { width: 1fr; }
    #errors-only { width: 25; }
    DataTable { background: #0f1a28; height: 1fr; }
    DataTable > .datatable--header { background: #1b3045; color: #a1dff2; text-style: bold; }
    DataTable > .datatable--cursor { background: #244861; color: #ffffff; }
    #probe-detail { height: 6; padding: 1; background: #132235; color: #a9bfd2; overflow-y: auto; }
    #network { padding: 1 2; }
    #events-note { height: 3; color: #8fa8be; }
    .setting { height: 5; }
    .setting Label { height: 1; color: #a9bfd2; }
    .setting Input { width: 30; }
    #settings-actions { height: 3; margin: 1 0; }
    Button { margin-right: 1; }
    #settings-note { color: #8fa8be; }
    #help-dialog { width: 76; max-width: 95%; height: auto; max-height: 90%; background: #132235; border: round #78d8f5; padding: 1 3; }
    Help { align: center middle; background: #000000 65%; }
    Help Button { margin-top: 1; }
    .compact Header { height: 1; }
    .compact #session { height: 1; padding: 0 1; }
    .compact #metrics { grid-size: 2; grid-columns: 1fr 1fr; height: 8; }
    .compact .metric { height: 4; }
    .compact .metric-value { height: 1; }
    .compact #overview-row { layout: vertical; }
    .compact #diagnosis-panel { width: 100%; margin-right: 0; }
    .compact #chain-panel { width: 100%; }
    .compact Tab { padding: 0 1; }
    """
    BINDINGS = [
        Binding("q", "quit", "Выход"), Binding("r", "refresh_now", "Обновить"),
        Binding("p", "pause", "Пауза"), Binding("s", "speed", "Скорость"),
        Binding("e", "export", "Отчёт"), Binding("question_mark", "help", "Справка"),
        *[Binding(str(i), f"tab('{name}')", show=False) for i, name in enumerate(
            ("overview", "probes", "network-tab", "events", "settings"), 1)],
    ]

    def __init__(self, monitor: Monitor):
        super().__init__()
        self.monitor = monitor
        self.paused = False
        self.sampling = False
        self.speed_running = False
        self.next_due = 0.0
        self.latest = None
        self.visible_probes = []
        self.last_storage_warning = None
        self.last_error = None

    def ui(self, selector, expected=None):
        return self.screen_stack[0].query_one(selector, expected)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Определяю систему и проверяю контрольные точки…", id="session", markup=False)
        with Grid(id="metrics"):
            yield Metric("СОСТОЯНИЕ", "health-metric")
            yield Metric("TCP / ЗАДЕРЖКА", "latency-metric")
            yield Metric("ТРАФИК АДАПТЕРА", "traffic-metric")
            yield Metric("ЦИКЛЫ БЕЗ ЗАМЕЧАНИЙ", "availability-metric")
        with TabbedContent(initial="overview", id="tabs"):
            with TabPane("1 Обзор", id="overview"):
                with VerticalScroll():
                    with Horizontal(id="overview-row"):
                        with Vertical(id="diagnosis-panel", classes="panel"):
                            yield Static("ДИАГНОЗ / ОСНОВАНИЯ", classes="section-title")
                            yield Static("Выполняется первый цикл…", id="diagnosis", markup=False)
                            yield Static("После проверки здесь появятся наблюдения, на которых основан диагноз.", id="evidence", markup=False)
                            yield Static("", id="next-step", markup=False)
                        with Vertical(id="chain-panel", classes="panel"):
                            yield Static("КОНТРОЛЬНАЯ ЦЕПОЧКА", classes="section-title")
                            yield DataTable(id="chain", cursor_type="row", show_header=False)
                    with Vertical(classes="panel"):
                        yield Static("ЗАДЕРЖКА TCP / ПОСЛЕДНИЕ 240 ЦИКЛОВ", classes="section-title")
                        yield Sparkline([], id="latency-chart")
                        yield Static("Пока нет успешных TCP-измерений.", id="latency-caption", markup=False)
                        yield Static("Нет измерений. S — разовый download-тест, до 5 МБ по умолчанию.", id="speed", markup=False)
            with TabPane("2 Проверки", id="probes"):
                with Horizontal(id="probe-toolbar"):
                    yield Input(placeholder="Поиск по адресу, сервису или ошибке…", id="filter")
                    yield Checkbox("Только ошибки", id="errors-only")
                yield DataTable(id="probe-table", cursor_type="row", zebra_stripes=True)
                yield Static("Выберите строку и нажмите Enter — здесь появится полный результат.", id="probe-detail", markup=False)
            with TabPane("3 Сеть", id="network-tab"):
                with VerticalScroll():
                    yield Static("Данные маршрутов и адаптера появятся после первого цикла.", id="network", markup=False)
            with TabPane("4 События", id="events"):
                yield Static("Инцидент начинается при замечании или сбое и закрывается после цикла OK. Последние 200; полная история — в JSONL-журнале.", id="events-note", markup=False)
                yield DataTable(id="incident-table", cursor_type="row", zebra_stripes=True)
            with TabPane("5 Настройки", id="settings"):
                with VerticalScroll():
                    yield Static("РЕЖИМ НАБЛЮДЕНИЯ", classes="section-title")
                    with Vertical(classes="setting"):
                        yield Label("Пауза между циклами, секунд (0.2–3600)")
                        yield Input(str(self.monitor.settings.interval), id="interval-input", type="number")
                    with Vertical(classes="setting"):
                        yield Label("Таймаут одной проверки, секунд (0.1–15)")
                        yield Input(str(self.monitor.settings.timeout), id="timeout-input", type="number")
                    with Horizontal(id="settings-actions"):
                        yield Button("Применить", id="apply-settings", variant="primary")
                        yield Button("Сохранить профиль", id="save-settings")
                    yield Static("", id="settings-note", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.ui("#probe-table", DataTable).add_columns("Проверка", "Цель / сервис", "Статус", "Время", "Результат")
        self.ui("#chain", DataTable).add_columns("Этап", "Ответ")
        self.ui("#incident-table", DataTable).add_columns("Начало", "Завершение", "Длительность", "Циклы", "Первый диагноз / последний код")
        self.set_class(self.size.width < 100, "compact")
        self.update_settings_note()
        self.set_interval(.25, self.tick)
        self.tick()

    def on_resize(self) -> None:
        self.set_class(self.size.width < 100, "compact")

    def tick(self) -> None:
        if self.paused:
            mode = "ПАУЗА · данные не обновляются"
        elif self.sampling:
            mode = "ПРОВЕРЯЮ"
        else:
            mode = f"МОНИТОРИНГ · следующий цикл через {max(0, self.next_due - time.monotonic()):.0f} с"
        suffix = f" · снимок {clock(self.latest.timestamp)} · {self.latest.duration_ms / 1000:.1f} с" if self.latest else " · ожидание первого результата"
        self.ui("#session", Static).update(mode + suffix + (f" · ОШИБКА: {self.last_error}" if self.last_error else ""))
        if not self.paused and not self.sampling and time.monotonic() >= self.next_due:
            self.sampling = True
            self.collect()

    @work(group="sample", exclusive=True)
    async def collect(self) -> None:
        self.sampling = True
        try:
            snapshot = await asyncio.to_thread(self.monitor.sample)
            self.monitor.accept(snapshot)
            self.latest = snapshot
            self.last_error = None
            self.render_snapshot()
            warning = self.monitor.storage_warning
            if warning and warning != self.last_storage_warning:
                self.notify(warning, severity="warning", timeout=8)
            self.last_storage_warning = warning
        except Exception as exc:
            self.last_error = str(exc)
            self.notify(f"Цикл не завершён: {exc}", severity="error", timeout=8)
        finally:
            self.sampling = False
            self.next_due = time.monotonic() + self.monitor.settings.interval

    def render_snapshot(self) -> None:
        s = self.latest
        if s is None:
            return
        status, color = STATUS[s.cause.status]
        card = self.ui("#health-metric", Metric)
        for name in STATUS:
            card.set_class(name == s.cause.status, name)
        card.show(Text(status, style=color), f"{s.platform} · {s.interface.name if s.interface else 'адаптер не определён'}")
        series = self.monitor.latency_series()
        current = [p.latency_ms for p in s.public_probes if p.outcome == "connected" and p.latency_ms is not None]
        jitter = statistics.mean(abs(b - a) for a, b in zip(series, series[1:])) if len(series) > 1 else None
        self.ui("#latency-metric", Metric).show(
            format_latency(statistics.median(current)) if current else "—",
            f"Джиттер {format_latency(jitter)} · TCP, не ping")
        rates = s.performance.interface_rates if s.performance else None
        self.ui("#traffic-metric", Metric).show(
            f"↓ {format_mbps(rates.rx_mbps)}" if rates else "—",
            f"↑ {format_mbps(rates.tx_mbps)}" if rates else "Нужны два цикла на одном адаптере")
        self.ui("#availability-metric", Metric).show(
            f"{self.monitor.healthy / self.monitor.total:.0%}", f"{self.monitor.healthy} из {self.monitor.total} · паузы исключены")
        self.ui("#diagnosis", Static).update(Text(s.cause.summary, style=color))
        self.ui("#evidence", Static).update("\n".join("• " + item for item in s.cause.evidence))
        self.ui("#next-step", Static).update("ДАЛЬШЕ\n" + "\n".join("→ " + item for item in s.cause.next_steps))
        table = self.ui("#chain", DataTable)
        table.clear()
        stages = [("Адаптер", [s.interface.status == "active"] if s.interface else []),
                  ("Шлюз / TCP", [s.gateway_probe.reachable] if s.gateway_probe else []),
                  ("Внешние IP", [p.reachable for p in s.public_probes]),
                  ("DNS системы", [p.ok for p in s.system_dns]),
                  ("DNS прямой", [p.ok for p in s.direct_dns]),
                  ("HTTP(S)", [p.ok for p in s.http_probes]),
                  ("Регионы", [p.ok for p in s.regional_services])]
        for name, values in stages:
            ok = sum(values)
            text = f"{ok}/{len(values)}" if values else "—"
            table.add_row(name, Text(text, style="#62e2ba" if values and all(values) else "#ffc875" if values else "#8fa8be"))
        self.ui("#latency-chart", Sparkline).data = series
        self.ui("#latency-caption", Static).update(
            f"Выборок: {len(series)} · минимум {min(series):.1f} мс · максимум {max(series):.1f} мс · джиттер {format_latency(jitter)}"
            if series else "Нет успешных TCP-соединений с контрольными IP; график пока пуст.")
        self.update_speed()
        self.render_probes()
        self.render_network()
        incidents = self.ui("#incident-table", DataTable)
        incidents.clear()
        for item in reversed(self.monitor.incidents):
            incidents.add_row(clock(item["started_at"]), clock(item["ended_at"]) if item["ended_at"] else "ОТКРЫТ",
                              duration(incident_duration(item, s.timestamp)), str(item["samples"]),
                              Text(item["summary"] + " / " + item.get("last_cause", item["cause"])))

    def render_probes(self) -> None:
        if self.latest is None:
            return
        search = self.ui("#filter", Input).value.casefold()
        errors = self.ui("#errors-only", Checkbox).value
        self.visible_probes = [row for row in probe_rows(self.latest)
                               if (not errors or not row["ok"]) and search in (row["kind"] + row["target"] + row["detail"]).casefold()]
        table = self.ui("#probe-table", DataTable)
        previous_row = table.cursor_row
        table.clear()
        for row in self.visible_probes:
            table.add_row(Text(row["kind"]), Text(row["target"]),
                          Text("OK" if row["ok"] else "ОШИБКА", style="#62e2ba" if row["ok"] else "#ff7e92"),
                          format_latency(row["latency"]), Text(row["detail"]))
        if self.visible_probes:
            table.move_cursor(row=min(previous_row, len(self.visible_probes) - 1))
            self.show_probe(min(previous_row, len(self.visible_probes) - 1))
        elif errors or search:
            self.ui("#probe-detail", Static).update("По выбранному фильтру проверок нет.")

    def render_network(self) -> None:
        s = self.latest
        def route(r):
            return f"{r.gateway} → {r.netif}" if r else "не обнаружен"
        info = s.interface
        lines = ["СИСТЕМА / ПУТЬ ТРАФИКА", "", f"Платформа: {s.platform}",
                 f"Активный default route: {route(s.active_default)}", f"Локальный маршрут: {route(s.local_default)}",
                 "Туннельные default routes: " + (", ".join(route(r) for r in s.tunnel_defaults) or "не обнаружены"),
                 f"Адаптер счётчиков: {info.name if info else 'не определён'}",
                 f"IPv4: {', '.join(info.ipv4) if info and info.ipv4 else '—'}",
                 f"IPv6: {', '.join(info.ipv6) if info and info.ipv6 else '—'}",
                 f"MAC: {info.mac if info and info.mac else '—'}", "",
                 "DNS / ПРОКСИ", "", "DNS из настроек системы: " + (", ".join(s.dns_servers_system) or "не определены"),
                 "Прямые контрольные DNS: " + (", ".join(s.dns_servers) or "отключены"),
                 "HTTP(S)-прокси из окружения: " + ("обнаружен; прямой TCP проверяется отдельно" if s.proxy_detected else "не обнаружен"),
                 "Проверки используют системную маршрутизацию; выбор адаптера меняет только счётчики.", "",
                 "ОГРАНИЧЕНИЯ СБОРА", "", *(s.collection_warnings or ["Системный сбор завершился без предупреждений."]), "",
                 "UDP DNS не подтверждает работу DoH/DoT. VPN без default route может не отображаться.",
                 "Прокси, заданный только в настройках ОС/браузера, может отличаться от прокси окружения."]
        self.ui("#network", Static).update("\n".join(lines))

    def update_speed(self) -> None:
        s = self.monitor.speed_result
        if self.speed_running:
            text = "DOWNLOAD / выполняется… интерфейс и мониторинг продолжают работать."
        elif s:
            text = (f"DOWNLOAD / {s.download_mbps} Мбит/с · {s.transferred_bytes / 1_000_000:.2f} МБ · "
                    f"TTFB {format_latency(s.ttfb_ms)} · {s.provider} · {clock(s.measured_at)}" if s.ok else
                    f"DOWNLOAD / {s.provider} · {s.error} · {clock(s.measured_at)}")
            text += "\nЭто короткая HTTP-выборка до выбранного узла, не оценка тарифа. S — повторить."
        else:
            text = f"S — download-тест до {self.monitor.settings.speedtest_bytes / 1_000_000:g} МБ. Автоматические замеры отключены."
        self.ui("#speed", Static).update(text)

    @on(Input.Changed, "#filter")
    @on(Checkbox.Changed, "#errors-only")
    def filter_probes(self) -> None:
        self.render_probes()

    @on(DataTable.RowSelected, "#probe-table")
    @on(DataTable.RowHighlighted, "#probe-table")
    def probe_selected(self, event: DataTable.RowSelected) -> None:
        self.show_probe(event.cursor_row)

    def show_probe(self, index: int) -> None:
        if 0 <= index < len(self.visible_probes):
            row = self.visible_probes[index]
            detail = f"{row['kind']} / {row['target']}\n{row['detail']}\n"
            attempts = row["data"].get("attempts", [])
            detail += " · ".join(f"Порт {a['port']}: {a['outcome']} ({a['error_code']})" for a in attempts)
            self.ui("#probe-detail", Static).update(detail)

    @on(DataTable.RowSelected, "#chain")
    def chain_selected(self) -> None:
        self.action_tab("probes")

    def action_tab(self, name: str) -> None:
        self.ui("#tabs", TabbedContent).active = name

    def action_refresh_now(self) -> None:
        if not self.sampling:
            self.sampling = True
            self.collect()

    def action_pause(self) -> None:
        self.paused = not self.paused
        if not self.paused:
            self.next_due = 0
        self.tick()

    def action_help(self) -> None:
        self.push_screen(Help())

    def action_export(self) -> None:
        if not self.monitor.history:
            self.notify("Дождитесь завершения первого цикла.")
            return
        try:
            path = self.monitor.export()
            self.notify(f"Отчёт сохранён: {path}", timeout=10)
        except OSError as exc:
            self.notify(f"Не удалось сохранить отчёт: {exc}", severity="error")

    def action_speed(self) -> None:
        if not self.speed_running:
            self.speed_running = True
            self.update_speed()
            self.run_speed()

    @work(group="speed", exclusive=True)
    async def run_speed(self) -> None:
        try:
            self.monitor.speed_result = await asyncio.to_thread(self.monitor.measure_speed)
            if self.latest:
                self.latest.performance.cloudflare_speed = self.monitor.speed_result
        except Exception as exc:
            self.notify(f"Download-тест не завершён: {exc}", severity="error")
        finally:
            self.speed_running = False
            self.update_speed()

    def update_settings_note(self) -> None:
        cfg = self.monitor.settings
        self.ui("#settings-note", Static).update(
            f"Контрольные точки: TCP {len(cfg.public_endpoints)} · имён DNS {len(cfg.dns_names)} · "
            f"DNS-серверов {len(cfg.dns_servers)} · HTTP {len(cfg.http_urls)} · региональных сервисов {len(cfg.regional_services)}.\n\n"
            "Период = длительность проверок + пауза между циклами. R запускает проверку сразу.\n"
            "Полный профиль целей редактируется в JSON и передаётся через --config.\n\n"
            f"Журнал: {self.monitor.journal.path if self.monitor.journal.enabled else 'отключён'}\n"
            "Ротация: 5 МБ × 4 файла. На экране хранится до 240 снимков и 200 инцидентов.\n"
            f"Отчёты: {self.monitor.journal.directory / 'reports'}\n\n"
            "Отчёт содержит сетевые адреса и ошибки. Просмотрите файл перед отправкой. "
            "Секреты из переменных окружения в отчёт не копируются.")

    @on(Button.Pressed, "#apply-settings")
    def apply_settings(self) -> None:
        from dataclasses import replace
        try:
            updated = replace(self.monitor.settings,
                              interval=float(self.ui("#interval-input", Input).value),
                              timeout=float(self.ui("#timeout-input", Input).value)).validate()
            if self.sampling or self.speed_running:
                self.notify("Дождитесь завершения текущей проверки, затем примените настройки.")
                return
            self.monitor.settings = updated
            self.next_due = 0
            self.update_settings_note()
            self.notify("Настройки применены к следующим циклам.")
        except ValueError as exc:
            self.notify(str(exc), severity="error")

    @on(Button.Pressed, "#save-settings")
    def save_settings(self) -> None:
        from uuid import uuid4
        try:
            self.monitor.journal.directory.mkdir(parents=True, exist_ok=True)
            path = self.monitor.journal.directory / f"profile-{uuid4().hex[:8]}.json"
            self.monitor.settings.save(path)
            self.notify(f"Профиль сохранён: {path}", timeout=10)
        except OSError as exc:
            self.notify(f"Не удалось сохранить профиль: {exc}", severity="error")
