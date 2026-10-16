from __future__ import annotations

import hashlib
import json
import statistics
from datetime import datetime


def network_id(snapshot):
    route = snapshot.local_default
    identity = [snapshot.platform, route.netif if route else None, route.gateway if route else None,
                snapshot.wifi.get("ssid") or snapshot.wifi.get("bssid")]
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:16]


def layer_results(s):
    def group(values):
        return {"status": "unknown" if not values else "ok" if all(values) else "partial" if any(values) else "failed",
                "passed": sum(values), "total": len(values)}
    return {
        "connectivity": group([p.reachable for p in s.public_probes] + [p.ok for p in s.http_probes]),
        "system_dns": group([p.ok for p in s.system_dns]),
        "direct_dns": group([p.ok for p in s.direct_dns]),
        "http": group([p.ok for p in s.http_probes]),
        "regions": group([p.ok for p in s.regional_services]),
        "gateway": group([s.gateway_probe.reachable] if s.gateway_probe else []),
    }


def connection_median(snapshot):
    values = [p.latency_ms for p in snapshot.public_probes if p.outcome == "connected" and p.latency_ms is not None]
    return statistics.median(values) if values else None


def baseline(s, previous):
    values = [connection_median(item) for item in previous]
    values = [value for value in values if value is not None]
    if len(values) < 20:
        return {"status": "learning", "samples": len(values), "minimum": 20}
    median = statistics.median(values)
    mad = statistics.median(abs(value - median) for value in values)
    threshold = max(median + 4 * 1.4826 * mad, median * 2, median + 20)
    current = connection_median(s)
    return {"status": "anomaly" if current is not None and current > threshold else "normal",
            "samples": len(values), "median_ms": round(median, 2), "threshold_ms": round(threshold, 2),
            "current_ms": current, "method": "median/MAD; same network and configured targets"}


def compare(before: dict, after: dict) -> dict:
    def target(p):
        return p["target"] + " /TCP " + ",".join(str(a["port"]) for a in p.get("attempts", []))
    def checks(snapshot):
        return {target(p): p["reachable"] for p in snapshot.get("public_probes", [])} | {
            p["url"]: p["ok"] for p in snapshot.get("http_probes", [])}
    a, b = checks(before), checks(after)
    common = sorted(set(a) & set(b))
    def latencies(snapshot):
        return {target(p): p.get("latency_ms") for p in snapshot.get("public_probes", []) if p.get("outcome") == "connected"}
    first, second = latencies(before), latencies(after)
    return {"before": before.get("timestamp"), "after": after.get("timestamp"),
            "route_before": before.get("active_default"), "route_after": after.get("active_default"),
            "dns_before": before.get("dns_servers_system"), "dns_after": after.get("dns_servers_system"),
            "wifi_before": before.get("wifi"), "wifi_after": after.get("wifi"),
            "same_targets": set(a) == set(b), "targets_compared": len(common),
            "changes": [{"target": target, "before": a[target], "after": b[target]} for target in common if a[target] != b[target]],
            "latency_changes": [{"target": target, "before_ms": first[target], "after_ms": second[target],
                "delta_ms": round(second[target] - first[target], 2)} for target in sorted(first.keys() & second.keys())
                if first[target] is not None and second[target] is not None],
            "note": "Сравнение наблюдений; причинность переключения VPN требует повторного эксперимента."}


def changes(before, after):
    result = []
    for key, label in (("active_default", "Маршрут"), ("dns_servers_system", "DNS"), ("interface", "Адаптер")):
        old, new = getattr(before, key), getattr(after, key)
        if key == "interface":
            old = (old.name, old.ipv4, old.ipv6) if old else None
            new = (new.name, new.ipv4, new.ipv6) if new else None
        if old != new:
            result.append(f"{label}: {old} → {new}")
    if before.wifi.get("ssid") != after.wifi.get("ssid"):
        result.append("Изменилась Wi-Fi сеть")
    return result
