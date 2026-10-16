"""Human-readable tool output; structured originals remain in the report."""
import json


def diagnostic_text(event):
    try:
        return _diagnostic_text(event)
    except (KeyError, TypeError, ValueError, AttributeError):
        return "Сохранённые данные инструмента / неполный формат\n" + json.dumps(event, ensure_ascii=False, indent=2)


def _diagnostic_text(event):
    result = event.get("result", {})
    tool = event.get("tool")
    if tool == "quality":
        rows = ["КАЧЕСТВО / " + result["target"], ""]
        def stats(label, data):
            return f"{label}: медиана {data['median_ms']} мс · p95 {data['p95_ms']} мс · джиттер {data['jitter_ms']} мс · ответов {data['samples']}/{data['attempts']}"
        rows.append(stats("В покое", result["idle"]))
        for name, data in result["stages"].items():
            transfer = data["transfer"]
            rows.append(f"{name}: {transfer.get('download_mbps', transfer.get('mbps', '—'))} Мбит/с · {transfer.get('error') or 'завершён'}")
            rows.append(stats("Под нагрузкой", data["loaded"]))
            rows.append(f"Рост задержки: {data['latency_increase_ms']} мс")
        udp = result["udp"]
        states = {"attention": "есть замечания", "insufficient_data": "недостаточно измерений; увеличьте объём теста в профиле", "measured_conditions_ok": "измеренные условия подходят"}
        rows += ["", "UDP: " + (f"потери {udp['loss_percent']}% ({udp['lost']}/{udp['sent']})" if "loss_percent" in udp else udp["reason"]),
                 "", "Профиль " + result["scenario"]["profile"] + ": " + states.get(result["scenario"]["status"], result["scenario"]["status"]),
                 result["scenario"]["note"], "Неудачные TCP-соединения не считаются потерями UDP."]
        return "\n".join(rows)
    if tool == "trace" and result.get("hops"):
        rows = ["МАРШРУТ / " + result["target"], "Узел   Адрес                      RTT / ответы"]
        for hop in result["hops"]:
            rows.append(f"{hop['hop']:>3}    {', '.join(hop['addresses']) or '*':<26} {hop['median_ms']} мс / {hop['responded']}/{hop['attempts']}")
        return "\n".join(rows + ["", result["note"]])
    if tool == "http":
        http = result["http"]
        rows = [f"HTTP / {http.get('status_code', '—')} · {http.get('final_url') or http.get('url')}", ""]
        labels = {"dns": "DNS", "tcp": "TCP", "tls": "TLS", "wait_first_byte": "Ожидание первого байта", "total": "Всего"}
        rows += [f"{labels[key]}: {value} мс" for key, value in http.get("timing_ms", {}).items()]
        rows += [http.get("error") or "", http.get("note") or "", "", "СЕРТИФИКАТ", json.dumps(result["certificate"], ensure_ascii=False, indent=2)]
        return "\n".join(rows)
    if tool == "comparison":
        return "СРАВНЕНИЕ ДО / ПОСЛЕ\n" + "\n".join(f"{key}: {value}" for key, value in result.items())
    return json.dumps(result, ensure_ascii=False, indent=2)
