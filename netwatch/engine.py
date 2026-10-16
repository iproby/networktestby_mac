from __future__ import annotations

import os
import statistics
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime

from . import __version__, core
from .native import collect_native, is_tunnel
from .settings import Settings
from .storage import Journal


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

    def sample(self) -> core.Snapshot:
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
            http = [pool.submit(core.http_probe, url, cfg.timeout) for url in cfg.http_urls]
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
        snapshot.duration_ms = round((time.monotonic() - started) * 1000, 1)
        snapshot.cause = core.build_assessment(snapshot)
        self.previous = counters
        self.previous_time = started
        self.previous_interface = interface.name if interface else None
        return snapshot

    def accept(self, snapshot: core.Snapshot) -> None:
        """Called on the UI/main thread, so exports see consistent session state."""
        self.total += 1
        self.healthy += snapshot.cause.status == "ok"
        self.history.append(snapshot)
        if snapshot.cause.status != "ok":
            if self.active_incident is None:
                self.active_incident = {"started_at": snapshot.timestamp, "ended_at": None,
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
        self._write({"event": "sample", "snapshot": asdict(snapshot)})

    def _write(self, event: dict) -> None:
        try:
            self.journal.append(event)
            self.storage_warning = None
        except OSError as exc:
            self.storage_warning = f"Не удалось записать журнал: {exc}"

    def measure_speed(self):
        cfg = self.settings
        return core.measure_download_speed(core.build_speedtest_url(cfg.speedtest_url, cfg.speedtest_bytes),
                                           cfg.speedtest_timeout, max_bytes=cfg.speedtest_bytes)

    def latency_series(self) -> list[float]:
        result = []
        for snapshot in self.history:
            values = [p.latency_ms for p in snapshot.public_probes if p.outcome == "connected" and p.latency_ms is not None]
            if values:
                result.append(statistics.median(values))
        return result

    def export(self):
        return self.journal.export({"application": "NetWatch", "version": __version__,
                                    "exported_at": core.iso_now(), "started_at": self.started_at,
                                    "total_samples": self.total, "healthy_samples": self.healthy,
                                    "settings": asdict(self.settings), "incidents": list(self.incidents),
                                    "snapshots": [asdict(s) for s in self.history],
                                    "note": "Contains local IP addresses, adapter names, targets and errors. Review before sharing."})


def incident_duration(incident: dict, now: str) -> float:
    return max(0, (datetime.fromisoformat(incident.get("ended_at") or now) -
                   datetime.fromisoformat(incident["started_at"])).total_seconds())
