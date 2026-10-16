from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4


def state_directory() -> Path:
    if sys.platform == "win32":
        root = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local" / "state")))
    return root / "NetWatch"


class Journal:
    """A bounded journal. Errors are surfaced by the caller, never swallowed here."""

    def __init__(self, directory: Path, enabled: bool = True):
        self.directory = directory
        self.enabled = enabled
        self.path = directory / "network-diagnostics.jsonl"
        self.max_bytes = 5_000_000
        from .history import History
        self.history = History(directory / "history.sqlite3")

    def append(self, event: dict) -> None:
        if not self.enabled:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
            for index in range(2, 0, -1):
                old = self.path.with_name(self.path.name + f".{index}")
                if old.exists():
                    old.replace(self.path.with_name(self.path.name + f".{index + 1}"))
            self.path.replace(self.path.with_name(self.path.name + ".1"))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        self.history.append(event)

    def export(self, report: dict) -> Path:
        destination = self.directory / "reports"
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = destination / f"netwatch-{stamp}-{uuid4().hex[:6]}.json"
        temporary = path.with_suffix(".tmp")
        try:
            with temporary.open("x", encoding="utf-8") as handle:
                json.dump(report, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            temporary.replace(path)
            from .reports import render_html
            path.with_suffix(".html").write_text(render_html(report), encoding="utf-8")
        finally:
            temporary.unlink(missing_ok=True)
        return path
