"""Native optional observations. Unknown values stay unknown."""
from __future__ import annotations

import csv
import io
import platform
import re
import shutil
from pathlib import Path

import psutil

from .core import run_command


def system_context():
    try:
        battery = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
    except (OSError, psutil.Error):
        battery = None
    try:
        cpu, memory, error = psutil.cpu_percent(interval=.05), psutil.virtual_memory().percent, None
    except (OSError, psutil.Error) as exc:
        cpu, memory, error = None, None, str(exc)
    return {"cpu_percent": cpu, "memory_percent": memory, "error": error,
            "battery_percent": battery.percent if battery else None,
            "on_battery": bool(battery and not battery.power_plugged)}


def wifi(interface=None):
    system = platform.system()
    try:
        if system == "Darwin":
            import CoreWLAN
            interfaces = CoreWLAN.CWWiFiClient.sharedWiFiClient().interfaces() or []
            adapter = next((i for i in interfaces if i.interfaceName() == interface), None)
            adapter = adapter or next((i for i in interfaces if i.ssid()), None)
            if adapter is None:
                return {"status": "unavailable", "reason": "Нет активного Wi-Fi интерфейса или доступа CoreWLAN"}
            channel = adapter.wlanChannel()
            rssi, noise = adapter.rssiValue(), adapter.noiseMeasurement()
            ssid = adapter.ssid()
            return {"status": "ok" if ssid else "limited", "source": "CoreWLAN", "interface": adapter.interfaceName(),
                    "ssid": ssid, "bssid": adapter.bssid(), "rssi_dbm": rssi or None, "noise_dbm": noise or None,
                    "snr_db": rssi - noise if rssi and noise else None, "tx_mbps": adapter.transmitRate() or None,
                    "channel": channel.channelNumber() if channel else None,
                    "reason": None if ssid else "SSID может требовать разрешения геолокации macOS"}
        if system == "Windows":
            return windows_wifi(interface)
        if system == "Linux":
            return linux_wifi(interface)
        return {"status": "unavailable", "reason": "Платформа не поддерживается"}
    except (ImportError, OSError, RuntimeError, AttributeError) as exc:
        return {"status": "unavailable", "reason": str(exc)}


def linux_wifi(interface=None):
    path = Path("/proc/net/wireless")
    text = path.read_text() if path.exists() else ""
    rows = [line.split() for line in text.splitlines()[2:] if ":" in line]
    row = next((r for r in rows if r[0].rstrip(":") == interface), rows[0] if rows else None)
    if not row:
        return {"status": "unavailable", "reason": "Активный Wi-Fi не обнаружен; возможно Ethernet или контейнер"}
    name = row[0].rstrip(":")
    result = {"status": "limited", "source": "/proc/net/wireless", "interface": name}
    if len(row) > 4:
        rssi = float(row[3].rstrip("."))
        result["rssi_dbm"] = rssi if rssi < 0 else None
        noise = float(row[4].rstrip("."))
        result["noise_dbm"] = noise if noise < 0 else None
        if rssi < 0 and noise < 0:
            result["snr_db"] = rssi - noise
    if shutil.which("iw"):
        rc, text, error = run_command(["iw", "dev", name, "link"], timeout=2)
        if rc == 0:
            result.update(parse_iw(text))
            result["source"] = "iw + /proc/net/wireless"
            result["status"] = "ok" if result.get("ssid") else "limited"
        else:
            result["reason"] = error.strip()
    else:
        result["reason"] = "Для SSID/канала/скорости установите системную утилиту iw"
    return result


def parse_iw(text):
    result = {}
    for field, pattern, transform in (
        ("ssid", r"SSID:\s*(.+)", str), ("bssid", r"Connected to ([\da-f:]+)", str),
        ("rssi_dbm", r"signal:\s*(-?[\d.]+) dBm", float),
        ("tx_mbps", r"tx bitrate:\s*([\d.]+) MBit/s", float), ("frequency_mhz", r"freq:\s*(\d+)", int)):
        match = re.search(pattern, text)
        if match:
            result[field] = transform(match[1].strip())
    frequency = result.get("frequency_mhz", 0)
    if frequency:
        result["channel"] = (frequency - 2407) // 5 if 2412 <= frequency <= 2472 else 14 if frequency == 2484 else (frequency - 5000) // 5 if 5000 <= frequency < 5925 else (frequency - 5950) // 5
    return result


def windows_wifi(interface=None):
    import ctypes as c
    from ctypes import wintypes as w
    class GUID(c.Structure):
        _fields_ = [("data", c.c_ubyte * 16)]
    class Interface(c.Structure):
        _fields_ = [("guid", GUID), ("description", w.WCHAR * 256), ("state", w.DWORD)]
    class SSID(c.Structure):
        _fields_ = [("length", w.ULONG), ("data", c.c_ubyte * 32)]
    class Association(c.Structure):
        _fields_ = [("ssid", SSID), ("bss_type", c.c_int), ("bssid", c.c_ubyte * 6), ("phy_type", c.c_int),
                    ("phy_index", w.ULONG), ("signal_quality", w.ULONG), ("rx_rate", w.ULONG), ("tx_rate", w.ULONG)]
    class Security(c.Structure):
        _fields_ = [("security", w.BOOL), ("one_x", w.BOOL), ("auth", c.c_int), ("cipher", c.c_int)]
    class Connection(c.Structure):
        _fields_ = [("state", c.c_int), ("mode", c.c_int), ("profile", w.WCHAR * 256), ("association", Association), ("security", Security)]
    api = c.WinDLL("wlanapi")
    api.WlanFreeMemory.argtypes = [c.c_void_p]
    handle, negotiated = w.HANDLE(), w.DWORD()
    code = api.WlanOpenHandle(2, None, c.byref(negotiated), c.byref(handle))
    if code:
        return {"status": "unavailable", "reason": f"WlanOpenHandle: {code}"}
    entries = c.c_void_p()
    try:
        code = api.WlanEnumInterfaces(handle, None, c.byref(entries))
        if code:
            return {"status": "unavailable", "reason": f"WlanEnumInterfaces: {code}"}
        count = c.cast(entries, c.POINTER(w.DWORD))[0]
        for index in range(min(count, 64)):
            info = Interface.from_address(entries.value + 8 + index * c.sizeof(Interface))
            if info.state != 1:
                continue
            size, opcode, data = w.DWORD(), w.DWORD(), c.c_void_p()
            code = api.WlanQueryInterface(handle, c.byref(info.guid), 7, None, c.byref(size), c.byref(data), c.byref(opcode))
            if code:
                continue
            try:
                a = c.cast(data, c.POINTER(Connection)).contents.association
                return {"status": "limited", "source": "Windows Native Wi-Fi API", "interface": info.description,
                        "ssid": bytes(a.ssid.data[:min(a.ssid.length, 32)]).decode("utf-8", "replace"),
                        "bssid": ":".join(f"{v:02x}" for v in a.bssid), "quality_percent": a.signal_quality,
                        "rx_mbps": a.rx_rate / 1000, "tx_mbps": a.tx_rate / 1000,
                        "reason": "RSSI/шум/канал не предоставлены этим API; процент сигнала не переводится в dBm"}
            finally:
                api.WlanFreeMemory(data)
        return {"status": "unavailable", "reason": "Нет подключённого Wi-Fi или разрешения WLAN"}
    finally:
        if entries.value:
            api.WlanFreeMemory(entries)
        api.WlanCloseHandle(handle, None)


def parse_nettop(text):
    rows = list(csv.reader(io.StringIO(text)))
    header = next((row for row in rows if "bytes_in" in row and "bytes_out" in row), None)
    if not header:
        return []
    result = []
    incoming, outgoing = header.index("bytes_in"), header.index("bytes_out")
    for row in rows[rows.index(header) + 1:]:
        if len(row) <= max(incoming, outgoing) or not re.search(r"\.\d+$", row[0]):
            continue
        try:
            name, pid = row[0].rsplit(".", 1)
            result.append({"pid": int(pid), "name": name, "rx_bytes": int(row[incoming]), "tx_bytes": int(row[outgoing])})
        except ValueError:
            continue
    return result


def parse_ss(text):
    """Linux TCP_INFO byte counters, summed over live sockets associated with a PID."""
    accounting, owners = {}, []
    for line in text.splitlines():
        if line and not line[0].isspace():
            owners = sorted(set(int(pid) for pid in re.findall(r"pid=(\d+)", line)))
        # Shared sockets have multiple owners; assigning all bytes would double count.
        if len(owners) != 1:
            continue
        values = {key: int(value) for key, value in re.findall(r"(bytes_received|bytes_acked):(\d+)", line)}
        if not values:
            continue
        row = accounting.setdefault(owners[0], {"rx_bytes": 0, "tx_bytes": 0})
        row["rx_bytes"] += values.get("bytes_received", 0)
        row["tx_bytes"] += values.get("bytes_acked", 0)
    return accounting


def process_activity():
    result = {"system": system_context(), "processes": [], "network_accounting": "unavailable"}
    counts = {}
    try:
        for connection in psutil.net_connections(kind="inet"):
            if connection.pid:
                counts[connection.pid] = counts.get(connection.pid, 0) + 1
    except (OSError, psutil.Error):
        result["connection_note"] = "Для списка всех сокетов могут требоваться дополнительные права"
    accounting = {}
    if platform.system() == "Linux" and shutil.which("ss"):
        rc, text, error = run_command(["ss", "-tinpH"], timeout=4)
        if rc == 0:
            accounting = parse_ss(text)
            if accounting:
                result["network_accounting"] = "Linux TCP_INFO via ss: received / acknowledged bytes of visible live TCP sockets"
                result["accounting_note"] = "Только видимые TCP-сокеты; UDP, закрытые и разделяемые сокеты исключены. Это не полный расход процесса за сессию."
        else:
            result["accounting_note"] = error.strip()
    if platform.system() == "Darwin" and shutil.which("nettop"):
        rc, text, error = run_command(["nettop", "-P", "-L", "1", "-J", "bytes_in,bytes_out", "-x"], timeout=4)
        if rc == 0:
            accounting = {p["pid"]: p for p in parse_nettop(text)}
            if accounting:
                result["network_accounting"] = "nettop cumulative process counters"
        else:
            result["accounting_note"] = error.strip()
    for p in psutil.process_iter(["pid", "name", "cpu_times", "memory_percent"]):
        try:
            if p.pid in counts or p.pid in accounting:
                info = p.info
                result["processes"].append({"pid": p.pid, "name": info["name"], "connections": counts.get(p.pid, 0),
                    "cpu_seconds": sum(info["cpu_times"][:2]) if info["cpu_times"] else None,
                    "memory_percent": info["memory_percent"], **{k: v for k, v in accounting.get(p.pid, {}).items() if k.endswith("bytes")}})
        except (OSError, psutil.Error):
            pass
    result["processes"] = sorted(result["processes"], key=lambda p: (p.get("rx_bytes", 0) + p.get("tx_bytes", 0), p["connections"]), reverse=True)[:30]
    if not accounting:
        result["accounting_note"] = "Доступны подключения/CPU/память; байты процессов не измерены. macOS использует nettop, Linux — ss/TCP_INFO; полные счётчики Windows требуют ETW-сборщика с дополнительными правами."
    return result
