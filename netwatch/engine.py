from __future__ import annotations

import os
import statistics
import time
import sqlite3
import psutil
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime
from uuid import uuid4

from . import __version__, core
from .native import collect_native, is_tunnel
from .settings import Settings
from .storage import Journal
from . import insights
from .budget import Budget
from .notifications import AlertPolicy, desktop
from .system import system_context, wifi


class Monitor:
    def __init__(self, settings: Settings, journal: Journal):
        self.settings = settings.validate()
        self.journal = journal
        self.started_at = core.iso_now()
        self.history = deque(maxlen=240)
        self.incidents = deque(maxlen=200)
        self.active_incident = None
        self.total = 0
        self.healthy = 0
        self.previous = None
        self.previous_time = None
        self.previous_interface = None
        self.speed_result = None
        self.storage_warning = None
        self.history_warning = None
        self.diagnostics = deque(maxlen=100)
        self.alerts = AlertPolicy()
        self.budget = Budget(settings, journal)
        self.offline = False
        self.comparison_before = None
        self.offline_archive = []
        self._baselines = {}
        self.journal.history.days = settings.history_days
        if journal.enabled and journal.history.path.exists():
            try:
                self.history.extend(core.snapshot_from_dict(e["snapshot"]) for e in journal.history.query(limit=240))
                self.incidents.extend(journal.history.incidents())
                self.diagnostics.extend(journal.history.query(kind="diagnostic", limit=100))
                for incident in self.incidents:
                    if not incident.get("ended_at") and self.history:
                        if incident.get("owner_pid") and incident["owner_pid"] != os.getpid():
                            try:
                                owner = psutil.Process(incident["owner_pid"])
                                if abs(owner.create_time() - incident.get("owner_created", 0)) < .01 and owner.is_running() and owner.status() != psutil.STATUS_ZOMBIE:
                                    continue  # Another live monitor still owns this incident.
                            except psutil.Error:
                                pass
                        samples = journal.history.query(since=incident["started_at"], until=self.history[-1].timestamp, limit=10000)
                        incident["samples"] = max(incident.get("samples", 0), sum(
                            e.get("incident_id") == incident.get("id") if "incident_id" in e else e["snapshot"]["cause"]["status"] != "ok"
                            for e in samples))
                        incident["sample_count_truncated"] = len(samples) == 10000
                        incident.update(ended_at=self.history[-1].timestamp, interrupted=True)
                        self._write({**incident, "event": "incident_closed"})
            except (OSError, sqlite3.Error, ValueError, TypeError, KeyError) as exc:
                self.history_warning = self.storage_warning = f"Не удалось восстановить историю: {exc}"

    def sample(self) -> core.Snapshot:
        if self.offline:
            raise ValueError("Отчёт открыт офлайн; сетевые операции отключены")
        started = time.monotonic()
        cfg = self.settings
        native = collect_native()
        routes = native.routes
        active = routes[0] if routes else None
        local = next((r for r in routes if not is_tunnel(r.netif) and r.flags != "T"), active)
        selected = cfg.interface or (active.netif if active else None)
        interface = native.interfaces.get(selected) if selected else next(
            (i for i in native.interfaces.values() if i.status == "active" and (i.ipv4 or i.ipv6)), None)
        if cfg.interface and interface is None:
            native.warnings.append(f"Выбранный интерфейс {cfg.interface!r} не найден.")
        counters = native.counters.get(interface.name) if interface else None
        if interface and interface.name != self.previous_interface:
            self.previous = self.previous_time = None

        # Submit independent checks together: one slow region cannot block UI updates.
        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="netwatch-probe") as pool:
            gateway = None
            if local and local.gateway not in ("0.0.0.0", "::", "link#", "on-link") and not local.gateway.startswith("link#"):
                gateway = pool.submit(core.tcp_probe, local.gateway, [53, 80, 443], cfg.timeout)
            public = [pool.submit(core.tcp_probe, host, ports, cfg.timeout)
                      for _, host, ports in (core.parse_public_endpoints(cfg.public_endpoints) if cfg.public_endpoints else [])]
            dns = [pool.submit(core.system_dns_lookup, name, cfg.timeout) for name in cfg.dns_names]
            direct = [pool.submit(core.dns_query, server, name, cfg.timeout)
                      for server in cfg.dns_servers for name in cfg.dns_names]
            http = [pool.submit(core.http_probe, url, cfg.timeout, cfg.http_assertions.get(url, {}).get("status"),
                                cfg.http_assertions.get(url, {}).get("contains")) for url in cfg.http_urls]
            regions = [pool.submit(core.regional_service_probe, tuple(item), cfg.timeout) for item in cfg.regional_services]
            snapshot = core.Snapshot(
                timestamp=core.iso_now(), active_default=active, local_default=local,
                tunnel_defaults=[r for r in routes if is_tunnel(r.netif) or r.flags == "T"],
                interface=interface, arp_has_gateway=False, dns_servers=cfg.dns_servers,
                gateway_probe=gateway.result() if gateway else None,
                public_probes=[f.result() for f in public], system_dns=[f.result() for f in dns],
                direct_dns=[f.result() for f in direct], http_probes=[f.result() for f in http],
                regional_services=[f.result() for f in regions],
                performance=core.PerformanceView(
                    interface_counters=counters,
                    interface_rates=core.compute_interface_rates(self.previous, self.previous_time, counters, started),
                    cloudflare_speed=self.speed_result,
                ),
                cause=core.make_assessment("degraded", "pending", "Проверка", 0, [], []),
                platform=native.platform, collection_warnings=native.warnings,
                proxy_detected=any(os.environ.get(key) for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy")),
                dns_servers_system=native.dns_servers,
            )
        snapshot.system = system_context()
        snapshot.wifi = wifi(interface.name if interface else None) if cfg.wifi_enabled else {"status": "disabled"}
        snapshot.network_id = insights.network_id(snapshot)
        snapshot.layers = insights.layer_results(snapshot)
        snapshot.cause = core.build_assessment(snapshot)
        snapshot.duration_ms = round((time.monotonic() - started) * 1000, 1)
        self.previous = counters
        self.previous_time = started
        self.previous_interface = interface.name if interface else None
        return snapshot

    def accept(self, snapshot: core.Snapshot) -> None:
        """Called on the UI/main thread, so exports see consistent session state."""
        if self.history:
            previous = self.history[-1]
            gap = (datetime.fromisoformat(snapshot.timestamp) - datetime.fromisoformat(previous.timestamp)).total_seconds()
            if gap > max(60, self.settings.interval * 4):
                snapshot.observations.append(f"Пробел в наблюдениях: {gap:.0f} с; доступность в этот период неизвестна")
                self.alerts = AlertPolicy()
                if self.active_incident:
                    self.active_incident.update(ended_at=previous.timestamp, interrupted=True)
                    self._write({"event": "incident_closed", **self.active_incident})
                    self.active_incident = None
            snapshot.observations.extend(insights.changes(previous, snapshot))
        signature = (snapshot.network_id, tuple(self.settings.public_endpoints))
        if signature not in self._baselines:
            if len(self._baselines) >= 16:
                self._baselines.pop(next(iter(self._baselines)))
            previous_samples = list(self.history)
            if self.journal.enabled:
                try:
                    previous_samples = [core.snapshot_from_dict(e["snapshot"]) for e in
                                        self.journal.history.query(network=snapshot.network_id, limit=720)]
                except (OSError, sqlite3.Error, ValueError, KeyError, TypeError) as exc:
                    self.storage_warning = f"История нормы недоступна: {exc}"
            self._baselines[signature] = deque((s for s in previous_samples if s.network_id == snapshot.network_id and
                s.cause.status == "ok" and [p.target for p in s.public_probes] == [p.target for p in snapshot.public_probes]), maxlen=720)
        previous_samples = self._baselines[signature]
        snapshot.baseline = insights.baseline(snapshot, previous_samples)
        if snapshot.cause.status == "ok" and snapshot.baseline.get("status") != "anomaly":
            previous_samples.append(snapshot)
        if snapshot.baseline.get("status") == "anomaly":
            snapshot.observations.append("Задержка существенно выше накопленной нормы этой сети")
        self.total += 1
        self.healthy += snapshot.cause.status == "ok"
        self.history.append(snapshot)
        if snapshot.cause.status != "ok":
            if self.active_incident is None:
                self.active_incident = {"id": uuid4().hex, "started_at": snapshot.timestamp, "ended_at": None,
                                        "owner_pid": os.getpid(), "owner_created": psutil.Process().create_time(),
                                        "cause": snapshot.cause.code, "summary": snapshot.cause.summary,
                                        "samples": 0}
                self.incidents.append(self.active_incident)
                self._write({"event": "incident_opened", **self.active_incident})
            self.active_incident["samples"] += 1
            self.active_incident["last_cause"] = snapshot.cause.code
        elif self.active_incident:
            self.active_incident["ended_at"] = snapshot.timestamp
            self._write({"event": "incident_closed", **self.active_incident})
            self.active_incident = None
        self._write({"event": "sample", "snapshot": asdict(snapshot),
                     "incident_id": self.active_incident["id"] if self.active_incident else None})
        notice = self.alerts.update(snapshot, self.settings)
        if notice and self.settings.notifications:
            outcome = desktop(*notice)
            self._write({"event": "notification", "timestamp": snapshot.timestamp, "title": notice[0], **outcome})
        try:
            self.budget.record(sum(p.bytes_read for p in snapshot.http_probes), len(snapshot.public_probes) +
                               len(snapshot.system_dns) + len(snapshot.direct_dns) + len(snapshot.http_probes) + len(snapshot.regional_services))
        except (OSError, sqlite3.Error, ValueError) as exc:
            self.storage_warning = f"Не удалось сохранить расход: {exc}"

    def _write(self, event: dict) -> None:
        try:
            self.journal.append(event)
            self.storage_warning = self.history_warning
        except (OSError, sqlite3.Error) as exc:
            self.storage_warning = f"Не удалось записать журнал: {exc}"

    def measure_speed(self):
        if self.offline:
            raise ValueError("Офлайн-режим")
        cfg = self.settings
        from .agent import bulk_opener
        with self.budget.reserve(cfg.speedtest_bytes) as meter:
            result = core.measure_download_speed(core.build_speedtest_url(cfg.speedtest_url, cfg.speedtest_bytes),
                                                cfg.speedtest_timeout, max_bytes=cfg.speedtest_bytes,
                                                opener=bulk_opener(cfg.speedtest_url, cfg.remote_agent_url))
            meter.update(bytes=result.transferred_bytes, requests=1)
            return result

    def latency_series(self) -> list[float]:
        result = []
        for snapshot in list(self.history)[-240:]:
            values = [p.latency_ms for p in snapshot.public_probes if p.outcome == "connected" and p.latency_ms is not None]
            if values:
                result.append(statistics.median(values))
        return result

    def export(self, anonymized=True):
        report = {"application": "NetWatch", "version": __version__,
                                    "exported_at": core.iso_now(), "started_at": self.started_at,
                                    "total_samples": self.total, "healthy_samples": self.healthy,
                                    "settings": asdict(self.settings), "incidents": list(self.incidents),
                  "snapshots": [asdict(s) for s in self.history], "diagnostics": list(self.diagnostics),
                  "note": "Review target names and error messages before sharing."}
        report["flight_recorder"] = []
        if self.journal.enabled:
            for incident in list(self.incidents)[-5:]:
                try:
                    report["flight_recorder"].append({"incident": incident, "context_minutes": 5,
                        "snapshots": self.journal.history.context(incident, limit=400),
                        "note": "До 400 снимков окна с выборкой до/во время/после; только собранные данные. Будущие 5 минут попадут в последующий экспорт."})
                except (OSError, ValueError, sqlite3.Error) as exc:
                    report["flight_recorder_warning"] = str(exc)
        from .reports import anonymize
        return self.journal.export(anonymize(report) if anonymized else report)

    def record_diagnostic(self, name, result):
        event = {"event": "diagnostic", "timestamp": core.iso_now(), "tool": name, "result": result}
        self.diagnostics.append(event)
        self._write(event)
        return event

    def next_interval(self):
        cfg = self.settings
        interval = cfg.interval
        if cfg.adaptive and self.history:
            healthy = len(self.history) >= 12 and all(s.cause.status == "ok" for s in list(self.history)[-12:])
            if healthy:
                interval *= 2
            if self.history[-1].system.get("on_battery"):
                interval *= 2
        return min(3600, interval)

    def set_settings(self, settings):
        self.settings = settings.validate()
        self.budget.settings = settings
        self.journal.history.days = settings.history_days

    def load_offline(self, report):
        self.offline = True
        self.journal.enabled = False
        self.history = deque((core.snapshot_from_dict(s) for s in report["snapshots"]), maxlen=10000)
        archive = {s.timestamp: s for s in self.history}
        for item in report.get("flight_recorder", []):
            for raw in item.get("snapshots", []):
                s = core.snapshot_from_dict(raw)
                archive[s.timestamp] = s
        self.offline_archive = sorted(archive.values(), key=lambda s: s.timestamp)[-10000:]
        self.incidents = deque(report.get("incidents", []), maxlen=200)
        self.diagnostics = deque(report.get("diagnostics", []), maxlen=100)
        self.total = report.get("total_samples", len(self.history))
        self.healthy = report.get("healthy_samples", sum(s.cause.status == "ok" for s in self.history))


def incident_duration(incident: dict, now: str) -> float:
    return max(0, (datetime.fromisoformat(incident.get("ended_at") or now) -
                   datetime.fromisoformat(incident["started_at"])).total_seconds())
