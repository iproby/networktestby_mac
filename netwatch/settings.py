from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from urllib.parse import urlsplit

from .core import DEFAULT_DNS_NAMES, DEFAULT_HTTP_URLS, DEFAULT_REGIONAL_SERVICES, parse_public_endpoints


@dataclass
class Settings:
    interval: float = 5.0
    timeout: float = 2.0
    dns_names: list[str] = field(default_factory=lambda: list(DEFAULT_DNS_NAMES))
    dns_servers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    public_endpoints: list[str] = field(default_factory=lambda: ["1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"])
    http_urls: list[str] = field(default_factory=lambda: list(DEFAULT_HTTP_URLS))
    regional_services: list[list[str]] = field(default_factory=lambda: [list(item) for item in DEFAULT_REGIONAL_SERVICES])
    interface: str | None = None
    speedtest_url: str = "https://speed.cloudflare.com/__down?bytes={bytes}"
    speedtest_bytes: int = 5_000_000
    speedtest_timeout: float = 15.0
    profile: str = "general"
    notifications: bool = False
    notify_after: int = 3
    recover_after: int = 2
    history_days: int = 7
    daily_budget_mb: float = 50.0
    adaptive: bool = True
    wifi_enabled: bool = True
    quality_samples: int = 10
    upload_url: str = "https://speed.cloudflare.com/__up"
    doh_url: str = "https://cloudflare-dns.com/dns-query"
    udp_endpoint: str | None = None
    remote_agent_url: str | None = None
    maintenance_until: str | None = None
    http_assertions: dict = field(default_factory=lambda: {
        "https://cp.cloudflare.com/generate_204": {"status": 204},
        "https://www.apple.com/library/test/success.html": {"status": 200, "contains": "Success"},
    })
    status_feeds: dict = field(default_factory=lambda: {
        "Cloudflare": "https://www.cloudflarestatus.com/api/v2/status.json",
        "GitHub": "https://www.githubstatus.com/api/v2/status.json",
    })

    def validate(self) -> Settings:
        import math
        for name, low, high in (("interval", .2, 3600), ("timeout", .1, 15), ("speedtest_timeout", 1, 60)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
                raise ValueError(f"{name}: допустимо от {low} до {high} секунд")
        if type(self.speedtest_bytes) is not int or not 1024 <= self.speedtest_bytes <= 20_000_000:
            raise ValueError("speedtest_bytes: допустимо 1024–20000000 байт")
        if self.profile not in ("general", "calls", "gaming", "vpn", "economy"):
            raise ValueError("Неизвестный профиль задачи")
        for name in ("notifications", "adaptive", "wifi_enabled"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name}: требуется true/false")
        for name, low, high in (("notify_after", 1, 20), ("recover_after", 1, 20), ("history_days", 1, 30), ("quality_samples", 3, 50)):
            if type(getattr(self, name)) is not int or not low <= getattr(self, name) <= high:
                raise ValueError(f"{name}: допустимо от {low} до {high}")
        if type(self.daily_budget_mb) not in (int, float) or not math.isfinite(self.daily_budget_mb) or not 1 <= self.daily_budget_mb <= 10000:
            raise ValueError("daily_budget_mb: допустимо 1–10000 МБ")
        if self.maintenance_until:
            from datetime import datetime
            if not isinstance(self.maintenance_until, str) or datetime.fromisoformat(self.maintenance_until).tzinfo is None:
                raise ValueError("maintenance_until: требуется ISO-дата с часовым поясом")
        if self.udp_endpoint is not None:
            parse_public_endpoints([self.udp_endpoint])
        if not isinstance(self.http_assertions, dict) or len(self.http_assertions) > 20:
            raise ValueError("http_assertions: требуется объект, максимум 20 проверок")
        for check in self.http_assertions.values():
            if not isinstance(check, dict) or set(check) - {"status", "contains"}:
                raise ValueError("HTTP-проверка поддерживает status и contains")
            if "status" in check and (type(check["status"]) is not int or not 100 <= check["status"] <= 599):
                raise ValueError("Некорректный ожидаемый HTTP-статус")
            if "contains" in check and (not isinstance(check["contains"], str) or len(check["contains"]) > 1000):
                raise ValueError("contains: строка до 1000 символов")
        if not isinstance(self.status_feeds, dict) or len(self.status_feeds) > 10 or any(not isinstance(k, str) for k in self.status_feeds):
            raise ValueError("status_feeds: объект с максимум 10 URL")
        for name in ("dns_names", "dns_servers", "public_endpoints", "http_urls"):
            value = getattr(self, name)
            if not isinstance(value, list) or len(value) > 20 or any(not isinstance(v, str) or not v for v in value):
                raise ValueError(f"{name}: требуется список непустых строк (максимум 20)")
        if not self.public_endpoints and not self.http_urls:
            raise ValueError("Добавьте хотя бы одну public_endpoints или http_urls")
        for server in self.dns_servers:
            ipaddress.ip_address(server)
        for name in self.dns_names:
            encoded = name.rstrip(".").encode("idna")
            if len(encoded) > 253 or any(not 1 <= len(label) <= 63 for label in encoded.split(b".")):
                raise ValueError(f"Некорректное DNS-имя: {name}")
        if len(self.dns_names) * len(self.dns_servers) > 40:
            raise ValueError("Допускается не более 40 прямых DNS-проверок в одном цикле")
        parse_public_endpoints(self.public_endpoints) if self.public_endpoints else None
        if self.interface is not None and (not isinstance(self.interface, str) or not self.interface.strip()):
            raise ValueError("interface: укажите имя адаптера или null")
        if not isinstance(self.regional_services, list) or len(self.regional_services) > 30:
            raise ValueError("regional_services: максимум 30 сервисов")
        codes = set()
        for item in self.regional_services:
            if not isinstance(item, (list, tuple)) or len(item) != 4 or any(not isinstance(v, str) or not v for v in item):
                raise ValueError("regional_services: формат [код, регион, имя, URL]")
            if item[0] in codes:
                raise ValueError(f"Повтор кода регионального сервиса: {item[0]}")
            codes.add(item[0])
        for url in (self.http_urls + [v[3] for v in self.regional_services] + [self.speedtest_url, self.upload_url, self.doh_url]
                    + list(self.http_assertions) + list(self.status_feeds.values()) + ([self.remote_agent_url] if self.remote_agent_url else [])):
            if not isinstance(url, str):
                raise ValueError("URL должен быть строкой")
            parsed = urlsplit(url)
            if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password
                    or any(c.isspace() or ord(c) < 32 for c in url) or parsed.port == 0):
                raise ValueError(f"Требуется HTTP(S) URL без встроенных учётных данных: {url}")
        return self

    def preset(self, name: str) -> Settings:
        from dataclasses import replace
        options = {
            "general": dict(interval=5, regional_services=[list(i) for i in DEFAULT_REGIONAL_SERVICES]),
            "calls": dict(interval=3, regional_services=[]),
            "gaming": dict(interval=2, regional_services=[]),
            "vpn": dict(interval=3, regional_services=[]),
            "economy": dict(interval=30, regional_services=[], daily_budget_mb=10),
        }
        if name not in options:
            raise ValueError("Неизвестный профиль")
        return replace(self, profile=name, **options[name]).validate()

    @classmethod
    def load(cls, path: Path) -> Settings:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Конфигурация должна быть объектом JSON")
        unknown = set(data) - {f.name for f in fields(cls)}
        if unknown:
            raise ValueError("Неизвестные настройки: " + ", ".join(sorted(unknown)))
        return cls(**data).validate()

    def save(self, path: Path) -> None:
        # Exclusive create protects an existing hand-edited profile.
        with path.open("x", encoding="utf-8") as handle:
            json.dump(asdict(self), handle, ensure_ascii=False, indent=2)
            handle.write("\n")
