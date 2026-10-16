"""Evidence-based assessments. A failed probe is not proof of a culprit."""
from __future__ import annotations

from .core import CauseAssessment, Snapshot, make_assessment


def assess(s: Snapshot) -> CauseAssessment:
    public = sum(p.reachable for p in s.public_probes)
    dns = sum(p.ok for p in s.system_dns)
    direct = sum(p.ok for p in s.direct_dns)
    http = sum(p.ok for p in s.http_probes)
    tunnel = bool(s.active_default and any(
        r.netif == s.active_default.netif for r in s.tunnel_defaults
    ))

    def result(status, code, summary, confidence, evidence, steps):
        return make_assessment(status, code, summary, confidence, evidence, steps)

    if s.interface is None:
        return result("degraded", "no_active_interface", "Активный интерфейс не определён.", .5,
                      s.collection_warnings or ["Нет интерфейса с маршрутом по умолчанию."],
                      ["Проверьте подключение Wi-Fi/Ethernet и доступность сетевых настроек системы."])
    if s.interface.status != "active" or not (s.interface.ipv4 or s.interface.ipv6):
        return result("down", "local_interface_down", "Адаптер отключён или потерял IP-адрес.", .92,
                      [f"{s.interface.name}: {s.interface.status}; нет рабочего подключения."],
                      ["Проверьте кабель, Wi-Fi и выдачу адреса по DHCP."])
    if not s.active_default and not s.local_default:
        if s.collection_warnings:
            return result("degraded", "collection_limited", "Не все системные данные доступны.", .4,
                          s.collection_warnings, ["Откройте вкладку «Сеть» и проверьте предупреждения сборщика."])
        return result("down", "no_default_route", "Не найден маршрут в интернет.", .88,
                      [f"{s.interface.name} имеет адрес, но default route отсутствует."],
                      ["Проверьте шлюз по умолчанию и настройки DHCP."])

    # Routers may silently filter control ports while forwarding traffic normally.
    if s.gateway_probe and not s.gateway_probe.reachable and not public and not http:
        return result("down", "gateway_unreachable", "Шлюз и внешние точки не отвечают.", .7,
                      [f"Шлюз {s.gateway_probe.target}: TCP-проверки без ответа.",
                       "Проблема локального линка вероятна, но фильтрация портов тоже возможна."],
                      ["Сравните связь с роутером и доступ в интернет на другом устройстве."])
    if s.public_probes and not public and not http:
        code = "tunnel_or_vpn_failure" if tunnel else "upstream_wan_failure"
        return result("down", code, "Нет ответа от внешних IP и контрольных сайтов.", .78,
                      ["Все выбранные TCP- и HTTP-проверки завершились неудачно."] +
                      (["Маршрут проходит через VPN/туннель."] if tunnel else []),
                      ["Проверьте VPN, правила доступа и WAN роутера; сравните с другой сетью."])
    if any(p.captive_portal for p in s.http_probes):
        return result("degraded", "possible_captive_portal", "Возможна страница входа в сеть.", .6,
                      ["Контрольный запрос с ожидаемым HTTP 204 получил страницу или перенаправление.",
                       "Альтернативы: изменение контрольного сервиса или вмешательство прокси."],
                      ["Проверьте адрес страницы входа и откройте его кнопкой в обзоре."])
    if s.system_dns and not dns:
        code = "local_dns_failure" if direct else "upstream_dns_failure" if s.direct_dns else "dns_unconfirmed"
        return result("degraded", code, "Системное разрешение имён не работает.", .85 if direct else .65,
                      ["Ни одно контрольное имя не разрешилось системным DNS.",
                       f"Прямой DNS: {direct}/{len(s.direct_dns)} успешных проверок." if s.direct_dns else "Прямой DNS не проверялся; источник сбоя не установлен."],
                      ["Проверьте DNS-серверы, VPN и DNS-фильтры. Сопоставьте ошибки во вкладке «Проверки»."])
    if s.http_probes and not http:
        return result("degraded", "http_layer_failure", "IP/DNS работают, контрольные HTTP(S)-запросы не проходят.", .72,
                      [p.error or f"HTTP {p.status_code}" for p in s.http_probes],
                      ["Проверьте captive portal, HTTPS-прокси, сертификаты и фильтрацию сайтов."])
    if s.public_probes and not public and http:
        return result("degraded", "proxy_path" if s.proxy_detected else "direct_tcp_unavailable",
                      "HTTP доступен; прямой TCP до контрольных IP не подтверждён.", .8,
                      ["Есть успешные HTTP-запросы при неудачных прямых TCP-проверках."] +
                      (["Обнаружены настройки HTTP(S)-прокси; пути TCP и HTTP могут различаться."] if s.proxy_detected else []),
                      ["Оценивайте прямую связность и прокси отдельно; это не доказательство сбоя провайдера."])
    if s.public_probes and 0 < public < len(s.public_probes):
        return result("degraded", "selective_upstream_instability", "Часть внешних IP-точек недоступна.", .65,
                      [f"Успешных TCP-проверок: {public}/{len(s.public_probes)}."],
                      ["Посмотрите ошибки конкретных точек; возможны разные маршруты или фильтрация портов."])
    if (any(not p.ok for p in s.http_probes) or any(not p.ok for p in s.system_dns)
            or any(not p.ok for p in s.regional_services)):
        return result("degraded", "service_partial", "Базовая сеть работает, часть сервисов недоступна.", .7,
                      ["Есть успешные проверки; отдельные имена или сайты вернули ошибки."],
                      ["Откройте «Проверки»: ответ 403/429 может означать ограничение сервиса, а не сбой сети."])
    if s.direct_dns and direct < len(s.direct_dns):
        return result("degraded", "direct_dns_restricted", "Системный DNS работает; прямые UDP DNS-проверки проходят не полностью.", .75,
                      [f"Прямой UDP DNS: {direct}/{len(s.direct_dns)}. Системный DNS: {dns}/{len(s.system_dns)}."],
                      ["Возможно, сеть разрешает только свой DNS или использует DoH/DoT. Сравните ошибки серверов."])
    if s.collection_warnings:
        return result("degraded", "collection_limited", "Сеть отвечает, часть данных системы недоступна.", .5,
                      s.collection_warnings, ["Посмотрите ограничения сборщика во вкладке «Сеть»."])
    if not s.public_probes and not s.http_probes:
        return result("degraded", "insufficient_checks", "Недостаточно проверок внешней связности.", .3,
                      ["TCP и HTTP-проверки не настроены."], ["Добавьте хотя бы одну контрольную точку."])
    return result("ok", "healthy", "Выбранные контрольные точки доступны.", .95,
                  [f"TCP {public}/{len(s.public_probes)} · DNS {dns}/{len(s.system_dns)} · HTTP {http}/{len(s.http_probes)}."] +
                  (["Шлюз не отвечает на контрольные TCP-порты, но внешние запросы проходят."]
                   if s.gateway_probe and not s.gateway_probe.reachable else []) +
                  ["Это результат выбранных проверок, а не гарантия доступности всего интернета."],
                  ["Оставьте монитор включённым, чтобы поймать следующий сбой."])
