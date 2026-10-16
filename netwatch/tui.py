"""Responsive Textual dashboard. Every number comes from the current session."""
from __future__ import annotations

import asyncio
import statistics
import time
import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (Button, Checkbox, DataTable, Footer, Header, Input,
                             Label, Select, Sparkline, Static, TabbedContent, TabPane)

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
                "1–8  Переключение вкладок\n"
                "R     Проверить сейчас\n"
                "P     Пауза / продолжить\n"
                "S     Замерить download (по умолчанию до 5 МБ)\n"
                "E     Экспортировать HTML + JSON-отчёт\n"
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
                "Журнал содержит IP-адреса. Экспорт обезличен по умолчанию: просмотрите его перед отправкой.",
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
    #target-table { height: 9; margin: 1 0; }
    .controls { height: 3; margin-bottom: 1; }
    .controls Select { width: 27; }
    .controls Input { width: 1fr; }
    .controls Button { min-width: 12; }
    #tool-output, #history-detail, #comparison-output { height: auto; padding: 1 2; }
    #history-table { height: 1fr; }
    #history-detail { height: 9; overflow-y: auto; background: #132235; }
    #assert-code { width: 12; }
    #trace-table { height: 12; }
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
            ("overview", "probes", "network-tab", "events", "settings", "history-tab", "tools-tab", "comparison-tab"), 1)],
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
        self.archive_rows = []
        self.target_rows = []
        self.target_selection = None
        self.tool_running = False
        self.tool_stop = False

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
                            yield Button("Открыть страницу входа", id="portal-open", disabled=True)
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
                yield Static("Инцидент начинается при замечании или сбое и закрывается после цикла OK. Enter на строке — контекст ±5 минут в истории. Последние 200.", id="events-note", markup=False)
                yield DataTable(id="incident-table", cursor_type="row", zebra_stripes=True)
            with TabPane("5 Настройки", id="settings"):
                with VerticalScroll():
                    yield Static("РЕЖИМ НАБЛЮДЕНИЯ", classes="section-title")
                    with Horizontal(classes="controls"):
                        yield Select([("Общий", "general"), ("Видеозвонки", "calls"), ("Игры", "gaming"), ("VPN", "vpn"), ("Экономия", "economy")], value=self.monitor.settings.profile, allow_blank=False, id="task-profile")
                        yield Button("Загрузить набор", id="apply-preset")
                    with Vertical(classes="setting"):
                        yield Label("Пауза между циклами, секунд (0.2–3600)")
                        yield Input(str(self.monitor.settings.interval), id="interval-input", type="number")
                    with Vertical(classes="setting"):
                        yield Label("Таймаут одной проверки, секунд (0.1–15)")
                        yield Input(str(self.monitor.settings.timeout), id="timeout-input", type="number")
                    with Horizontal(id="settings-actions"):
                        yield Button("Применить", id="apply-settings", variant="primary")
                        yield Button("Сохранить профиль", id="save-settings")
                    yield Checkbox("Локальные уведомления об устойчивых сбоях", self.monitor.settings.notifications, id="notify-enabled")
                    yield Checkbox("Адаптировать интервал при стабильной сети / питании от батареи", self.monitor.settings.adaptive, id="adaptive-enabled")
                    with Vertical(classes="setting"):
                        yield Label("Суточный лимит тестовых загрузок, МБ")
                        yield Input(str(self.monitor.settings.daily_budget_mb), id="budget-input", type="number")
                    with Vertical(classes="setting"):
                        yield Label("Хранить историю, дней (1–30; дополнительно действует лимит размера)")
                        yield Input(str(self.monitor.settings.history_days), id="retention-input", type="integer")
                    yield Static("КОНТРОЛЬНЫЕ ТОЧКИ / выберите строку для изменения", classes="section-title")
                    yield DataTable(id="target-table", cursor_type="row")
                    with Horizontal(classes="controls"):
                        yield Select([("HTTP(S)", "http_urls"), ("IP:порт", "public_endpoints"), ("DNS-имя", "dns_names"), ("DNS-сервер", "dns_servers"), ("Регион CODE|Регион|Имя|URL", "regional_services")], value="http_urls", allow_blank=False, id="target-kind")
                        yield Input(placeholder="URL, IP:порт, имя или региональный сервис", id="target-input")
                    with Horizontal(classes="controls"):
                        yield Button("Добавить", id="target-add")
                        yield Button("Изменить", id="target-edit")
                        yield Button("Удалить", id="target-remove")
                    with Horizontal(classes="controls"):
                        yield Input(placeholder="HTTP-код", id="assert-code", type="integer")
                        yield Input(placeholder="Ожидаемый текст (необязательно)", id="assert-text")
                        yield Button("Условие HTTP", id="apply-assertion")
                    yield Static("", id="settings-note", markup=False)
                    with Horizontal(classes="controls"):
                        yield Button("В фон", id="background-start")
                        yield Button("Статус фона", id="background-status")
                        yield Button("Остановить фон", id="background-stop")
            with TabPane("6 История", id="history-tab"):
                with Horizontal(classes="controls"):
                    yield Select([("Последний час", 1), ("24 часа", 24), ("7 дней", 168)], value=24, allow_blank=False, id="history-range")
                    yield Button("Обновить архив", id="history-refresh")
                yield DataTable(id="history-table", cursor_type="row", zebra_stripes=True)
                yield Static("Выберите снимок. Показаны до 1000 последних записей выбранного периода.", id="history-detail", markup=False)
            with TabPane("7 Диагностика", id="tools-tab"):
                with Horizontal(classes="controls"):
                    from .tools import TOOLS
                    yield Select([(label, name) for name, label in TOOLS.items()], value="wifi", allow_blank=False, id="tool-select")
                    yield Input(placeholder="Узел / URL; пусто — цель из профиля", id="tool-target")
                    yield Button("Запустить", id="run-tool", variant="primary")
                    yield Button("Остановить", id="stop-tool", disabled=True)
                yield Checkbox("MTR: повторять трассировку до остановки", False, id="trace-repeat")
                yield DataTable(id="trace-table", cursor_type="row", zebra_stripes=True)
                with VerticalScroll():
                    yield Static("Выберите инструмент. Качество под нагрузкой расходует до двух лимитов speedtest_bytes; трассировка и UDP используют только выбранные цели.", id="tool-output", markup=False)
            with TabPane("8 Сравнение", id="comparison-tab"):
                with Horizontal(classes="controls"):
                    yield Button("Снимок ДО", id="compare-before")
                    yield Button("Проверить ПОСЛЕ", id="compare-after", variant="primary")
                with VerticalScroll():
                    yield Static("Сохраните текущий снимок, переключите VPN или сеть самостоятельно, затем запустите повторную проверку. Маршруты системы приложение не меняет.", id="comparison-output", markup=False)
        yield Footer()

    def on_mount(self) -> None:
        self.ui("#probe-table", DataTable).add_columns("Проверка", "Цель / сервис", "Статус", "Время", "Результат")
        self.ui("#chain", DataTable).add_columns("Этап", "Ответ")
        self.ui("#incident-table", DataTable).add_columns("Начало", "Завершение", "Длительность", "Циклы", "Первый диагноз / последний код")
        self.ui("#target-table", DataTable).add_columns("Тип", "Контрольная точка")
        self.ui("#history-table", DataTable).add_columns("Время", "Статус", "Адаптер", "Диагноз")
        self.ui("#trace-table", DataTable).add_columns("TTL", "Адреса", "Средняя RTT", "p95", "Ответы/пробы", "Последний раунд")
        self.ui("#trace-table", DataTable).display = False
        self.set_class(self.size.width < 100, "compact")
        self.update_settings_note()
        self.render_targets()
        if self.monitor.offline:
            self.paused = True
            self.title = "NETWATCH / ОФЛАЙН"
            self.latest = self.monitor.history[-1] if self.monitor.history else None
            if self.latest:
                self.render_snapshot()
        self.refresh_archive()
        self.set_interval(.25, self.tick)
        self.tick()

    def on_resize(self) -> None:
        self.set_class(self.size.width < 100, "compact")

    def tick(self) -> None:
        # Timers can run during Textual's teardown after children have unmounted.
        if self._exit or not self.screen_stack or not self.screen_stack[0].query("#session"):
            return
        if self.monitor.offline:
            mode = "ОФЛАЙН / сохранённый отчёт · сетевые операции отключены"
        elif self.paused:
            mode = "ПАУЗА · данные не обновляются"
        elif self.sampling:
            mode = "ПРОВЕРЯЮ"
        else:
            mode = f"МОНИТОРИНГ · следующий цикл через {max(0, self.next_due - time.monotonic()):.0f} с"
        suffix = f" · снимок {clock(self.latest.timestamp)} · {self.latest.duration_ms / 1000:.1f} с" if self.latest else " · ожидание первого результата"
        self.ui("#session", Static).update(mode + suffix + (f" · ОШИБКА: {self.last_error}" if self.last_error else ""))
        if not self.monitor.offline and not self.paused and not self.sampling and time.monotonic() >= self.next_due:
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
            self.next_due = time.monotonic() + self.monitor.next_interval()

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
            f"{self.monitor.healthy / max(1, self.monitor.total):.0%}", f"{self.monitor.healthy} из {self.monitor.total} · паузы исключены")
        self.ui("#diagnosis", Static).update(Text(s.cause.summary, style=color))
        self.ui("#evidence", Static).update("\n".join("• " + item for item in s.cause.evidence + s.observations))
        self.ui("#next-step", Static).update("ДАЛЬШЕ\n" + "\n".join("→ " + item for item in s.cause.next_steps))
        portal = self.ui("#portal-open", Button)
        portal.display = any(p.captive_portal for p in s.http_probes)
        portal.disabled = self.monitor.offline or not portal.display
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

    @on(Button.Pressed, "#portal-open")
    def open_portal(self) -> None:
        if self.monitor.offline or not self.latest:
            return
        from urllib.parse import urlsplit
        import webbrowser
        url = next((p.final_url or p.url for p in self.latest.http_probes if p.captive_portal), "")
        parsed = urlsplit(url)
        if parsed.scheme in ("http", "https") and parsed.hostname and not parsed.username and not parsed.password:
            webbrowser.open(url)

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
        w, b, system = s.wifi, s.baseline, s.system
        lines += ["", "WI-FI / НАТИВНЫЕ ДАННЫЕ", f"Источник: {w.get('source', '—')} · {w.get('status', 'не измерялось')}",
                  f"Сеть: {w.get('ssid') or '—'} · канал: {w.get('channel') or '—'}",
                  f"RSSI: {w.get('rssi_dbm', '—')} dBm · шум: {w.get('noise_dbm', '—')} dBm · SNR: {w.get('snr_db', '—')} dB",
                  f"Скорость линка TX: {w.get('tx_mbps', '—')} Мбит/с", w.get('reason') or "",
                  "", "НОРМА ЭТОЙ СЕТИ", f"Состояние: {b.get('status', '—')} · измерений: {b.get('samples', 0)} / минимум 20",
                  f"Обычная задержка: {b.get('median_ms', '—')} мс · порог отклонения: {b.get('threshold_ms', '—')} мс",
                  "", "КОНТЕКСТ УСТРОЙСТВА", f"CPU: {system.get('cpu_percent', '—')}% · память: {system.get('memory_percent', '—')}%",
                  f"Батарея: {system.get('battery_percent', '—')}% · питание от батареи: {'да' if system.get('on_battery') else 'нет / неизвестно'}",
                  "", "СЛОИ ПРОВЕРОК"]
        labels = {"connectivity": "Внешняя связность", "system_dns": "Системный DNS", "direct_dns": "Прямой DNS", "http": "HTTP", "regions": "Сервисы", "gateway": "Шлюз TCP"}
        states = {"ok": "OK", "failed": "ошибки", "partial": "частично", "unknown": "нет измерений"}
        lines += [f"{labels.get(key, key)}: {states.get(value['status'], value['status'])} · {value['passed']}/{value['total']}" for key, value in s.layers.items()]
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
        if self.monitor.offline:
            self.notify("Отчёт открыт офлайн")
            return
        if not self.sampling:
            self.sampling = True
            self.collect()

    def action_pause(self) -> None:
        if self.monitor.offline:
            return
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
            self.notify(f"Отчёт JSON + HTML сохранён: {path}", timeout=10)
        except (OSError, ValueError, sqlite3.Error) as exc:
            self.notify(f"Не удалось сохранить отчёт: {exc}", severity="error")

    def action_speed(self) -> None:
        if self.monitor.offline:
            self.notify("Отчёт открыт офлайн")
            return
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
            "Цели и HTTP-условия редактируются выше; профиль также поддерживает --config.\n\n"
            f"Журнал: {self.monitor.journal.path if self.monitor.journal.enabled else 'отключён'}\n"
            f"SQLite-архив: до {cfg.history_days} дней / 150 МБ сжатых данных. JSONL: 5 МБ × 4 файла.\n"
            f"Отчёты: {self.monitor.journal.directory / 'reports'}\n\n"
            "Отчёт содержит сетевые адреса и ошибки. Просмотрите файл перед отправкой. "
            "Экспорт E обезличивает адреса и создаёт JSON + автономный HTML.\n\n"
            + json.dumps(self.monitor.budget.summary(), ensure_ascii=False, indent=2))

    @on(Button.Pressed, "#apply-settings")
    def apply_settings(self) -> None:
        from dataclasses import replace
        try:
            updated = replace(self.monitor.settings,
                              interval=float(self.ui("#interval-input", Input).value),
                              timeout=float(self.ui("#timeout-input", Input).value),
                              daily_budget_mb=float(self.ui("#budget-input", Input).value),
                              history_days=int(self.ui("#retention-input", Input).value),
                              notifications=self.ui("#notify-enabled", Checkbox).value,
                              adaptive=self.ui("#adaptive-enabled", Checkbox).value).validate()
            if self.sampling or self.speed_running or self.tool_running:
                self.notify("Дождитесь завершения текущей проверки, затем примените настройки.")
                return
            self.monitor.set_settings(updated)
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

    def render_targets(self):
        table = self.ui("#target-table", DataTable)
        table.clear()
        self.target_rows = []
        for group in ("http_urls", "public_endpoints", "dns_names", "dns_servers", "regional_services"):
            for index, value in enumerate(getattr(self.monitor.settings, group)):
                label = "|".join(value) if isinstance(value, (list, tuple)) else value
                self.target_rows.append((group, index, label))
                table.add_row(group, Text(label))

    @on(DataTable.RowSelected, "#target-table")
    def select_target(self, event: DataTable.RowSelected):
        if 0 <= event.cursor_row < len(self.target_rows):
            self.target_selection = self.target_rows[event.cursor_row]
            group, _, value = self.target_selection
            self.ui("#target-kind", Select).value = group
            self.ui("#target-input", Input).value = value
            check = self.monitor.settings.http_assertions.get(value, {}) if group == "http_urls" else {}
            self.ui("#assert-code", Input).value = str(check.get("status", ""))
            self.ui("#assert-text", Input).value = check.get("contains", "")

    @on(Button.Pressed, "#target-add")
    @on(Button.Pressed, "#target-edit")
    @on(Button.Pressed, "#target-remove")
    def edit_target(self, event: Button.Pressed):
        import copy
        if self.sampling or self.tool_running or self.speed_running:
            self.notify("Дождитесь завершения текущей проверки")
            return
        try:
            cfg = copy.deepcopy(self.monitor.settings)
            action = event.button.id
            group = self.ui("#target-kind", Select).value
            value = self.ui("#target-input", Input).value.strip()
            value = value.split("|", 3) if group == "regional_services" else value
            if action == "target-add":
                getattr(cfg, group).append(value)
            else:
                if not self.target_selection:
                    raise ValueError("Выберите строку через Enter")
                original, index, _ = self.target_selection
                if action == "target-remove":
                    if original == "http_urls":
                        cfg.http_assertions.pop(getattr(cfg, original)[index], None)
                    del getattr(cfg, original)[index]
                else:
                    if original != group:
                        raise ValueError("Для изменения типа удалите старую точку и добавьте новую")
                    if original == "http_urls":
                        check = cfg.http_assertions.pop(getattr(cfg, original)[index], None)
                        if check is not None:
                            cfg.http_assertions[value] = check
                    getattr(cfg, group)[index] = value
            self.monitor.set_settings(cfg.validate())
            self.target_selection = None
            self.render_targets()
            self.update_settings_note()
            self.notify("Контрольные точки обновлены; сохраните профиль для следующего запуска")
        except (ValueError, TypeError, IndexError) as exc:
            self.notify(str(exc), severity="error")

    @on(Button.Pressed, "#apply-assertion")
    def apply_assertion(self):
        import copy
        if self.sampling or self.tool_running or self.speed_running:
            self.notify("Дождитесь завершения проверки")
            return
        try:
            cfg = copy.deepcopy(self.monitor.settings)
            url = self.ui("#target-input", Input).value.strip()
            if url not in cfg.http_urls:
                raise ValueError("Выберите HTTP-точку")
            code = self.ui("#assert-code", Input).value
            text = self.ui("#assert-text", Input).value
            check = {}
            if code:
                check["status"] = int(code)
            if text:
                check["contains"] = text
            cfg.http_assertions[url] = check
            self.monitor.set_settings(cfg.validate())
            self.notify("HTTP-условие применено")
        except ValueError as exc:
            self.notify(str(exc), severity="error")

    @on(Button.Pressed, "#apply-preset")
    def apply_preset(self):
        if self.sampling or self.tool_running or self.speed_running:
            self.notify("Дождитесь завершения проверки")
            return
        cfg = self.monitor.settings.preset(self.ui("#task-profile", Select).value)
        self.monitor.set_settings(cfg)
        self.ui("#interval-input", Input).value = str(cfg.interval)
        self.ui("#timeout-input", Input).value = str(cfg.timeout)
        self.ui("#budget-input", Input).value = str(cfg.daily_budget_mb)
        self.render_targets()
        self.update_settings_note()
        self.notify("Профиль задачи применён; телеметрия реального звонка/игры не подменяется TCP-проверками")

    @on(Button.Pressed, "#history-refresh")
    def history_clicked(self):
        self.refresh_archive()

    @on(DataTable.RowSelected, "#incident-table")
    def incident_selected(self, event):
        incidents = list(reversed(self.monitor.incidents))
        if 0 <= event.cursor_row < len(incidents):
            self.action_tab("history-tab")
            self.incident_context(dict(incidents[event.cursor_row]))

    @work(group="archive", exclusive=True)
    async def incident_context(self, incident):
        try:
            if self.monitor.offline or not self.monitor.journal.enabled:
                start = datetime.fromisoformat(incident["started_at"]) - timedelta(minutes=5)
                end = datetime.fromisoformat(incident.get("ended_at") or iso_now()) + timedelta(minutes=5)
                source = self.monitor.offline_archive if self.monitor.offline else self.monitor.history
                self.archive_rows = [s for s in source if start <= datetime.fromisoformat(s.timestamp) <= end][-1000:]
            else:
                from .core import snapshot_from_dict
                records = await asyncio.to_thread(self.monitor.journal.history.context, incident, limit=1000)
                self.archive_rows = [snapshot_from_dict(s) for s in records]
            self.render_archive()
            self.ui("#history-detail", Static).update(f"Инцидент {incident['started_at']} · контекст ±5 минут · {len(self.archive_rows)} снимков (до 1000). Пробелы означают отсутствие наблюдений.")
        except Exception as exc:
            self.notify(f"Контекст недоступен: {exc}", severity="warning")

    def render_archive(self):
        table = self.ui("#history-table", DataTable)
        table.clear()
        for snapshot in self.archive_rows:
            table.add_row(datetime.fromisoformat(snapshot.timestamp).astimezone().strftime("%d.%m %H:%M:%S"),
                          snapshot.cause.status, snapshot.interface.name if snapshot.interface else "—", Text(snapshot.cause.summary))

    @work(group="archive", exclusive=True)
    async def refresh_archive(self):
        try:
            hours = int(self.ui("#history-range", Select).value)
            reference = datetime.fromisoformat(self.monitor.history[-1].timestamp) if self.monitor.offline and self.monitor.history else datetime.now(timezone.utc)
            since = (reference - timedelta(hours=hours)).isoformat()
            if self.monitor.offline:
                self.archive_rows = [s for s in self.monitor.offline_archive if s.timestamp >= since][-1000:]
            else:
                from .core import snapshot_from_dict
                records = await asyncio.to_thread(self.monitor.journal.history.query, since=since, limit=1000)
                self.archive_rows = [snapshot_from_dict(record["snapshot"]) for record in records]
            self.render_archive()
            self.ui("#history-detail", Static).update(f"Снимков: {len(self.archive_rows)}. Выберите строку для разбора; архив ограничен 1000 последними записями периода.")
        except Exception as exc:
            self.notify(f"Архив недоступен: {exc}", severity="warning")

    @on(DataTable.RowSelected, "#history-table")
    @on(DataTable.RowHighlighted, "#history-table")
    def history_selected(self, event):
        if 0 <= event.cursor_row < len(self.archive_rows):
            s = self.archive_rows[event.cursor_row]
            self.ui("#history-detail", Static).update(s.timestamp + "\n" + s.cause.summary + "\n" +
                "\n".join("• " + item for item in s.cause.evidence + s.observations) + "\n" +
                "\n".join("→ " + item for item in s.cause.next_steps))

    @on(Button.Pressed, "#run-tool")
    def tool_clicked(self):
        if self.monitor.offline:
            self.notify("Офлайн-режим: доступны только сохранённые результаты")
            if self.monitor.diagnostics:
                from .presentation import diagnostic_text
                self.ui("#tool-output", Static).update("\n\n".join(diagnostic_text(item) for item in self.monitor.diagnostics))
            return
        if self.tool_running:
            return
        self.tool_running = True
        self.tool_stop = False
        self.ui("#run-tool", Button).disabled = True
        self.ui("#stop-tool", Button).disabled = self.ui("#tool-select", Select).value != "trace"
        self.ui("#tool-output", Static).update("Измерение выполняется… остальные вкладки доступны.")
        self.run_tool(self.ui("#tool-select", Select).value, self.ui("#tool-target", Input).value.strip())

    @on(Button.Pressed, "#stop-tool")
    def stop_tool(self):
        self.tool_stop = True
        self.notify("Остановка после текущей пробы (до 30 секунд)")

    @work(group="diagnostic", exclusive=True)
    async def run_tool(self, tool, target):
        from .tools import run
        from .presentation import diagnostic_text
        from .measurements import MTRSession
        try:
            session = MTRSession()
            while True:
                result = await asyncio.to_thread(run, self.monitor, tool, target)
                table = self.ui("#trace-table", DataTable)
                table.display = tool == "trace" and bool(result["result"].get("hops"))
                if table.display:
                    merged = session.update(result["result"])
                    result = {**result, "result": merged}
                    table.clear()
                    for hop in merged["hops"]:
                        table.add_row(str(hop["hop"]), Text(", ".join(hop["addresses"]) or "*"), format_latency(hop["average_ms"]),
                                      format_latency(hop["p95_ms"]), f"{hop['responded']}/{hop['attempts']}", str(hop["last_round"]))
                self.ui("#tool-output", Static).update(
                    f"МАРШРУТ / {merged['target']} · раундов: {merged['rounds']}\n\n" + merged["note"] if table.display else diagnostic_text(result))
                if tool != "trace" or not table.display or self.tool_stop or not self.ui("#trace-repeat", Checkbox).value:
                    break
                for _ in range(10):
                    await asyncio.sleep(.2)
                    if self.tool_stop:
                        break
                if self.tool_stop:
                    break
            if tool == "trace" and session.rounds:
                self.monitor.record_diagnostic("trace", result["result"])
        except Exception as exc:
            self.ui("#tool-output", Static).update(f"Измерение не завершено: {exc}")
        finally:
            self.tool_running = False
            self.ui("#run-tool", Button).disabled = False
            self.ui("#stop-tool", Button).disabled = True
            self.update_settings_note()

    @on(Button.Pressed, "#compare-before")
    def capture_before(self):
        if self.monitor.offline or not self.latest:
            self.notify("Нужен текущий живой снимок")
            return
        self.monitor.comparison_before = asdict(self.latest)
        self.ui("#comparison-output", Static).update(f"Снимок ДО сохранён: {self.latest.timestamp}\nПереключите VPN/подключение и нажмите «Проверить ПОСЛЕ».")

    @on(Button.Pressed, "#compare-after")
    def compare_after(self):
        if self.monitor.offline or self.sampling or self.monitor.comparison_before is None:
            self.notify("Сначала сохраните снимок ДО и дождитесь завершения текущей проверки")
            return
        self.sampling = True
        self.collect_comparison()

    @work(group="sample", exclusive=True)
    async def collect_comparison(self):
        from .insights import compare
        from .presentation import diagnostic_text
        try:
            self.latest = await asyncio.to_thread(self.monitor.sample)
            self.monitor.accept(self.latest)
            result = self.monitor.record_diagnostic("comparison", compare(self.monitor.comparison_before, asdict(self.latest)))
            self.ui("#comparison-output", Static).update(diagnostic_text(result))
            self.render_snapshot()
        except Exception as exc:
            self.notify(str(exc), severity="error")
        finally:
            self.sampling = False
            self.next_due = time.monotonic() + self.monitor.next_interval()

    @on(Button.Pressed, "#background-start")
    @on(Button.Pressed, "#background-status")
    @on(Button.Pressed, "#background-stop")
    def background_clicked(self, event):
        if self.monitor.offline:
            self.notify("Офлайн-режим")
            return
        self.manage_background(event.button.id.removeprefix("background-"))

    @work(group="background", exclusive=True)
    async def manage_background(self, action):
        from .background import manage
        try:
            result = await asyncio.to_thread(manage, action, self.monitor.journal.directory, self.monitor.settings)
            self.notify(json.dumps(result, ensure_ascii=False), timeout=10)
        except Exception as exc:
            self.notify(str(exc), severity="error", timeout=10)
