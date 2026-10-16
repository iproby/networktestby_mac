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

    def validate(self) -> Settings:
        import math
        for name, low, high in (("interval", .2, 3600), ("timeout", .1, 15), ("speedtest_timeout", 1, 60)):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
                raise ValueError(f"{name}: допустимо от {low} до {high} секунд")
        if type(self.speedtest_bytes) is not int or not 1024 <= self.speedtest_bytes <= 20_000_000:
            raise ValueError("speedtest_bytes: допустимо 1024–20000000 байт")
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
        for url in self.http_urls + [v[3] for v in self.regional_services] + [self.speedtest_url]:
            if not isinstance(url, str):
                raise ValueError("URL должен быть строкой")
            parsed = urlsplit(url)
            if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password
                    or any(c.isspace() or ord(c) < 32 for c in url) or parsed.port == 0):
                raise ValueError(f"Требуется HTTP(S) URL без встроенных учётных данных: {url}")
        return self

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
