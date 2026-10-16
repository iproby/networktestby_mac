from contextlib import contextmanager
from datetime import datetime, timezone
from threading import RLock
import sqlite3


class Budget:
    def __init__(self, settings, journal):
        self.settings, self.journal = settings, journal
        self.lock = RLock()
        self.day = None
        self.used = self.payload = self.requests = self.pending = 0
        self.storage_error = None

    def refresh(self):
        day = datetime.now(timezone.utc).date().isoformat()
        if day != self.day:
            try:
                usage = self.journal.history.usage(day) if self.journal.enabled else {}
            except (OSError, sqlite3.Error) as exc:
                self.storage_error = str(exc)
                raise ValueError("Не удалось прочитать сохранённый бюджет: " + str(exc)) from exc
            self.used, self.payload, self.requests = (usage.get(k, 0) for k in ("bulk_bytes", "payload_bytes", "control_requests"))
            self.day = day

    def summary(self):
        with self.lock:
            try:
                self.refresh()
            except ValueError:
                pass
            return {"day_utc": self.day, "bulk_bytes": self.used, "payload_bytes": self.payload,
                    "control_requests": self.requests, "reserved_bytes": self.pending,
                    "limit_bytes": int(self.settings.daily_budget_mb * 1_000_000),
                    "storage_error": self.storage_error,
                    "note": "Лимит относится к тестовым загрузкам; TCP/TLS/IP-заголовки и трафик других процессов не измеряются."}

    @contextmanager
    def reserve(self, maximum):
        identity = None
        with self.lock:
            self.refresh()
            if self.storage_error:
                raise ValueError("Тестовая загрузка недоступна: расход не удалось сохранить. " + self.storage_error)
            if maximum + self.used + self.pending > self.settings.daily_budget_mb * 1_000_000:
                raise ValueError("Суточный лимит тестовых загрузок исчерпан; измените бюджет в профиле")
            if self.journal.enabled:
                identity = self.journal.history.reserve(self.day, maximum, int(self.settings.daily_budget_mb * 1_000_000))
            self.pending += maximum
        meter = {"bytes": 0, "requests": 0}
        try:
            yield meter
        finally:
            with self.lock:
                self.pending -= maximum
                self.refresh()
                self.used += meter["bytes"]
                self.record(meter["bytes"], meter["requests"], meter["bytes"])
                if identity:
                    self.journal.history.release(identity)

    def record(self, payload, requests, bulk=0):
        with self.lock:
            self.refresh()
            self.payload += payload
            self.requests += requests
            if self.journal.enabled:
                try:
                    self.journal.append({"event": "traffic", "timestamp": datetime.now(timezone.utc).isoformat(),
                                         "payload_bytes": payload, "bulk_bytes": bulk, "control_requests": requests})
                except (OSError, sqlite3.Error) as exc:
                    self.storage_error = str(exc)
                    raise
