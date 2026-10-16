"""Durable, bounded flight recorder. Connections are scoped to each operation."""
from __future__ import annotations

import json
import sqlite3
import zlib
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path


class History:
    def __init__(self, path: Path, days: int = 7, max_bytes: int = 150_000_000):
        self.path, self.days, self.max_bytes = path, days, max_bytes

    @contextmanager
    def connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            connection.execute("PRAGMA busy_timeout=10000")
            connection.execute("PRAGMA auto_vacuum=INCREMENTAL")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, kind TEXT NOT NULL, network TEXT NOT NULL, payload BLOB NOT NULL)")
            connection.execute("CREATE INDEX IF NOT EXISTS events_time ON events(kind,timestamp)")
            connection.execute("CREATE INDEX IF NOT EXISTS events_network ON events(network,kind,timestamp)")
            connection.execute("CREATE TABLE IF NOT EXISTS daily_usage (day TEXT PRIMARY KEY, payload INTEGER NOT NULL, requests INTEGER NOT NULL, bulk INTEGER NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS reservations (id TEXT PRIMARY KEY, maximum INTEGER NOT NULL, created TEXT NOT NULL)")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def append(self, event: dict) -> None:
        snapshot = event.get("snapshot", {})
        timestamp = snapshot.get("timestamp") or event.get("timestamp") or event.get("ended_at") or event.get("started_at")
        timestamp = timestamp or datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        network = snapshot.get("network_id", "")
        payload = zlib.compress(json.dumps(event, ensure_ascii=False).encode(), 3)
        with self.connect() as connection:
            cursor = connection.execute("INSERT INTO events(timestamp,kind,network,payload) VALUES(?,?,?,?)",
                                        (timestamp, event.get("event", "unknown"), network, payload))
            if event.get("event") == "traffic":
                connection.execute("INSERT INTO daily_usage(day,payload,requests,bulk) VALUES(?,?,?,?) ON CONFLICT(day) DO UPDATE SET payload=payload+excluded.payload,requests=requests+excluded.requests,bulk=bulk+excluded.bulk",
                                   (timestamp[:10], event.get("payload_bytes", 0), event.get("control_requests", 0), event.get("bulk_bytes", 0)))
            if cursor.lastrowid % 100 == 0:
                cutoff = (datetime.fromisoformat(timestamp) - timedelta(days=self.days)).isoformat()
                connection.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
                connection.execute("DELETE FROM daily_usage WHERE day < ?", (cutoff[:10],))
                size = connection.execute("SELECT coalesce(sum(length(payload)),0) FROM events").fetchone()[0]
                while size > self.max_bytes:
                    connection.execute("DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT 1000)")
                    size = connection.execute("SELECT coalesce(sum(length(payload)),0) FROM events").fetchone()[0]
            connection.commit()
            if cursor.lastrowid % 100 == 0:
                connection.execute("PRAGMA incremental_vacuum(1000)")

    def query(self, *, kind="sample", since=None, until=None, network=None, limit=240) -> list[dict]:
        if not self.path.exists():
            return []
        clauses, values = ["kind = ?"], [kind]
        for column, operator, value in (("timestamp", ">=", since), ("timestamp", "<=", until), ("network", "=", network)):
            if value is not None:
                clauses.append(f"{column} {operator} ?")
                values.append(value)
        values.append(max(1, min(int(limit), 10000)))
        with self.connect() as connection:
            rows = connection.execute("SELECT payload FROM events WHERE " + " AND ".join(clauses) +
                                      " ORDER BY id DESC LIMIT ?", values).fetchall()
        try:
            return [json.loads(zlib.decompress(row[0])) for row in reversed(rows)]
        except (zlib.error, UnicodeError, json.JSONDecodeError, TypeError) as exc:
            raise ValueError("Повреждена запись SQLite-архива; текущие измерения можно продолжать") from exc

    def incidents(self, limit=200) -> list[dict]:
        opened = self.query(kind="incident_opened", limit=limit)
        closed = self.query(kind="incident_closed", limit=limit)
        by_id = {item.get("id", item.get("started_at")): item for item in opened}
        for item in closed:
            by_id[item.get("id", item.get("started_at"))] = item
        return sorted(by_id.values(), key=lambda item: item["started_at"])[-limit:]

    def context(self, incident: dict, minutes=5, limit=2000) -> list[dict]:
        opened = datetime.fromisoformat(incident["started_at"])
        closed = datetime.fromisoformat(incident.get("ended_at") or datetime.now(timezone.utc).isoformat())
        ranges = ((opened - timedelta(minutes=minutes), opened), (opened, closed), (closed, closed + timedelta(minutes=minutes)))
        phases = [[e["snapshot"] for e in self.query(since=start.isoformat(), until=end.isoformat(), limit=10000)]
                  for start, end in ranges]
        def thin(rows, count):
            if len(rows) <= count:
                return rows
            return [rows[round(i * (len(rows) - 1) / max(1, count - 1))] for i in range(count)]
        # Preserve pre/post evidence even for long incidents with thousands of samples.
        before, after = thin(phases[0], max(1, limit // 4)), thin(phases[2], max(1, limit // 4))
        middle = thin(phases[1], max(1, limit - len(before) - len(after)))
        unique = {s["timestamp"]: s for s in before + middle + after}
        return sorted(unique.values(), key=lambda s: s["timestamp"])

    def usage(self, day: str) -> dict:
        if not self.path.exists():
            return {}
        with self.connect() as connection:
            row = connection.execute("SELECT payload,requests,bulk FROM daily_usage WHERE day=?", (day,)).fetchone()
        return dict(zip(("payload_bytes", "control_requests", "bulk_bytes"), row or (0, 0, 0)))

    def reserve(self, day, maximum, limit):
        """Serialize bulk-test admission across foreground/background processes."""
        from uuid import uuid4
        now = datetime.now(timezone.utc)
        identity = uuid4().hex
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            # All tools are bounded below 15 minutes; crashed clients expire conservatively.
            connection.execute("DELETE FROM reservations WHERE created < ?", ((now - timedelta(minutes=15)).isoformat(),))
            used = connection.execute("SELECT bulk FROM daily_usage WHERE day=?", (day,)).fetchone()
            pending = connection.execute("SELECT coalesce(sum(maximum),0) FROM reservations").fetchone()[0]
            if (used[0] if used else 0) + pending + maximum > limit:
                raise ValueError("Суточный лимит тестовых загрузок исчерпан или зарезервирован другим процессом")
            connection.execute("INSERT INTO reservations VALUES(?,?,?)", (identity, maximum, now.isoformat()))
        return identity

    def release(self, identity):
        with self.connect() as connection:
            connection.execute("DELETE FROM reservations WHERE id=?", (identity,))
