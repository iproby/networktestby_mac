"""Portable offline reports with opt-out anonymization and no remote assets."""
from __future__ import annotations

import copy
import html
import ipaddress
import json
import re
import math
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def anonymize(report: dict) -> dict:
    aliases = {}
    def alias(value, kind):
        key = (kind, value)
        if key not in aliases:
            aliases[key] = f"<{kind}-{sum(k[0] == kind for k in aliases) + 1}>"
        return aliases[key]
    def scrub(value, key=""):
        if isinstance(value, dict):
            return {scrub(name): scrub(item, name) for name, item in value.items() if name.lower() not in ("token", "authorization", "api_key")}
        if isinstance(value, list):
            return [scrub(item, key) for item in value]
        if not isinstance(value, str):
            return value
        if key.lower() in ("ssid", "bssid", "mac", "username", "hostname") and value:
            return alias(value, key.upper())
        # Remove credentials/query values from URLs embedded in errors as well as settings.
        def url(match):
            try:
                parsed = urlsplit(match[0])
                port = parsed.port
            except ValueError:
                return "<URL-REDACTED>"
            host = parsed.hostname or ""
            if ":" in host:
                host = "[" + host + "]"
            if port:
                host += ":" + str(port)
            return urlunsplit((parsed.scheme, host, parsed.path,
                               urlencode([(k, "REDACTED") for k, _ in parse_qsl(parsed.query)]), ""))
        value = re.sub(r"https?://[^\s\"<>]+", url, value)
        value = re.sub(r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", lambda m: alias(m[0], "MAC"), value)
        value = re.sub(r"(?<![\w])(?:\d{1,3}\.){3}\d{1,3}(?![\w])", lambda m: alias(m[0], "IP"), value)
        def ipv6(match):
            try:
                ipaddress.IPv6Address(match[0].split("%")[0])
                return alias(match[0], "IP")
            except ValueError:
                return match[0]
        return re.sub(r"(?<![\w])(?:[0-9a-fA-F]{0,4}:){2,}[A-Za-z0-9:.%_-]*(?![\w])", ipv6, value)
    result = scrub(copy.deepcopy(report))
    result["anonymized"] = True
    return result


def render_html(report: dict) -> str:
    escape = lambda value: html.escape(str(value))
    snapshots = report.get("snapshots", [])
    rows = []
    for snapshot in snapshots:
        cause = snapshot.get("cause", {})
        evidence = " · ".join(cause.get("evidence", []))
        rows.append("<tr>" + "".join(f"<td>{escape(value)}</td>" for value in (
            snapshot.get("timestamp", ""), cause.get("status", "unknown"), cause.get("summary", ""), evidence)) + "</tr>")
    incidents = "".join("<li>" + escape(f"{item['started_at']} — {item.get('ended_at') or 'открыт'}: {item.get('summary', '')}") + "</li>"
                        for item in report.get("incidents", []))
    diagnostic = escape(json.dumps(report.get("diagnostics", []), ensure_ascii=False, indent=2))
    from statistics import median
    series = []
    for snapshot in snapshots:
        points = [p["latency_ms"] for p in snapshot.get("public_probes", []) if p.get("outcome") == "connected" and isinstance(p.get("latency_ms"), (int, float))]
        series.append(median(points) if points else None)
    valid = [point for point in series if point is not None]
    chart = "<p>Нет успешных измерений TCP-задержки</p>"
    if valid:
        maximum = max(1, max(valid))
        segments, current = [], []
        for index, point in enumerate(series):
            if point is None:
                if current:
                    segments.append(current)
                current = []
            else:
                current.append(f"{20 + index * 960 / max(1, len(series) - 1):.1f},{175 - point * 150 / maximum:.1f}")
        if current:
            segments.append(current)
        chart = '<svg viewBox="0 0 1000 200" role="img" aria-label="Медиана TCP-задержки по снимкам" style="width:100%;background:#111e2d">' + ''.join('<polyline points="' + ' '.join(segment) + '" fill="none" stroke="#73d8ee" stroke-width="3"/>' for segment in segments) + '</svg>'
        chart += f"<small>TCP handshake · максимум {maximum:.1f} мс · {len(series)} снимков слева направо; пробелы означают отсутствие измерений.</small>"
    context = "".join("<details><summary>Контекст инцидента " + escape(item.get("incident", {}).get("started_at", "")) +
                      " · ±5 минут</summary><pre>" + escape(json.dumps(item.get("snapshots", []), ensure_ascii=False, indent=2)) + "</pre></details>"
                      for item in report.get("flight_recorder", []))
    return f"""<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>NetWatch — отчёт</title><style>
body{{background:#0b1420;color:#dce9f5;font:16px system-ui;margin:32px auto;padding:0 20px;max-width:1400px}}
h1,h2{{color:#73d8ee}}table{{border-collapse:collapse;width:100%}}td,th{{padding:12px;text-align:left;border-bottom:1px solid #2b4056;vertical-align:top}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}small{{color:#a4bbce}}
</style><h1>NetWatch / разбор подключения</h1><p>{escape(report.get('exported_at',''))}</p>
<small>Снимков: {len(snapshots)}. Данные {'обезличены' if report.get('anonymized') else 'содержат сетевые адреса'}. Отчёт работает без интернета.</small>
<h2>Инциденты</h2><ul>{incidents or '<li>Нет зарегистрированных инцидентов</li>'}</ul>
{context}<h2>Задержка подключения</h2>{chart}
<h2>Хронология и основания</h2><table><tr><th>Время</th><th>Статус</th><th>Диагноз</th><th>Наблюдения</th></tr>{''.join(rows)}</table>
<h2>Дополнительные измерения</h2><pre>{diagnostic}</pre></html>"""


def load_report(path):
    if path.stat().st_size > 30_000_000:
        raise ValueError("Отчёт превышает 30 МБ")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("application") != "NetWatch" or not isinstance(data.get("snapshots"), list):
        raise ValueError("Ожидался JSON-отчёт NetWatch")
    if len(data["snapshots"]) > 10000:
        raise ValueError("Слишком много снимков в отчёте")
    from .core import snapshot_from_dict
    from datetime import datetime
    try:
        for raw in data["snapshots"]:
            snapshot = snapshot_from_dict(raw)
            validate_snapshot(snapshot)
            if snapshot.cause.status not in ("ok", "degraded", "down") or datetime.fromisoformat(snapshot.timestamp).tzinfo is None:
                raise ValueError("Некорректное состояние/время")
        for key in ("incidents", "diagnostics", "flight_recorder"):
            if not isinstance(data.get(key, []), list):
                raise ValueError("Некорректный список " + key)
        context_count = 0
        for item in data.get("flight_recorder", []):
            for raw in item.get("snapshots", []):
                context_count += 1
                s = snapshot_from_dict(raw)
                validate_snapshot(s)
                if s.cause.status not in ("ok", "degraded", "down") or datetime.fromisoformat(s.timestamp).tzinfo is None:
                    raise ValueError("Некорректный контекст инцидента")
        if context_count > 10000:
            raise ValueError("Слишком много снимков в контексте")
        for item in data.get("incidents", []):
            datetime.fromisoformat(item["started_at"])
            if item.get("ended_at"):
                datetime.fromisoformat(item["ended_at"])
            if not isinstance(item.get("samples"), int) or not all(isinstance(item.get(k), str) for k in ("cause", "summary")):
                raise ValueError("Некорректный инцидент")
        for key in ("total_samples", "healthy_samples"):
            if key in data and (type(data[key]) is not int or data[key] < 0):
                raise ValueError("Некорректный счётчик")
    except (KeyError, TypeError, AttributeError, ValueError) as exc:
        raise ValueError("Повреждённый JSON-отчёт NetWatch: " + str(exc)) from exc
    return data


def validate_snapshot(s):
    """Reject malformed primitive types before a report reaches UI renderers."""
    def text(value):
        if not isinstance(value, str):
            raise ValueError("Ожидалась строка")
    def strings(value):
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError("Ожидался список строк")
    def number(value):
        if value is not None and (type(value) not in (int, float) or not math.isfinite(value)):
            raise ValueError("Некорректное числовое значение")
    text(s.timestamp)
    text(s.platform)
    for value in (s.observations, s.collection_warnings, s.dns_servers, s.dns_servers_system, s.cause.evidence, s.cause.next_steps):
        strings(value)
    for value in (s.cause.status, s.cause.code, s.cause.summary, s.cause.culprit):
        text(value)
    for value in (s.duration_ms, s.cause.confidence):
        if value is None:
            raise ValueError("Отсутствует длительность/уверенность")
        number(value)
    for value in (s.wifi, s.system, s.baseline, s.layers):
        if not isinstance(value, dict):
            raise ValueError("Ожидался объект наблюдений")
    for layer in s.layers.values():
        if not isinstance(layer, dict) or layer.get("status") not in ("ok", "failed", "partial", "unknown") or any(type(layer.get(k)) is not int for k in ("passed", "total")):
            raise ValueError("Некорректный слой проверок")
    if s.interface:
        text(s.interface.name)
        text(s.interface.status)
        strings(s.interface.ipv4)
        strings(s.interface.ipv6)
    for route in [s.active_default, s.local_default] + s.tunnel_defaults:
        if route:
            for value in (route.gateway, route.netif, route.flags):
                text(value)
    for p in s.public_probes + ([s.gateway_probe] if s.gateway_probe else []):
        text(p.target)
        text(p.outcome)
        text(p.detail)
        number(p.latency_ms)
        if type(p.reachable) is not bool:
            raise ValueError("Некорректный статус TCP")
    for p in s.http_probes + s.regional_services + s.system_dns + s.direct_dns:
        if type(p.ok) is not bool:
            raise ValueError("Некорректный статус проверки")
        number(p.latency_ms)
        if p.error is not None:
            text(p.error)
    for p in s.http_probes + s.regional_services:
        text(p.url)
        if p.error is not None:
            text(p.error)
    for p in s.system_dns + s.direct_dns:
        text(p.name)
        text(p.server)
