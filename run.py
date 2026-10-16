#!/usr/bin/env python3
"""One-command bootstrap. Keeps dependencies isolated and forwards all CLI flags."""
from __future__ import annotations

import os
import platform
import subprocess
import sys
import venv
from pathlib import Path


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if sys.version_info < (3, 9):
        print("NetWatch требует Python 3.9+. Установите Python с https://www.python.org/downloads/", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parent
    env = root / ".venv"
    python = env / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    marker = env / ".netwatch-requirements"
    try:
        requirements = (root / "requirements.txt").read_text(encoding="utf-8")
        if not python.exists():
            print(f"NetWatch · {platform.system()} · создаю изолированную среду…", file=sys.stderr, flush=True)
            venv.EnvBuilder(with_pip=True).create(env)
        probe_code = "import textual, psutil, dns, certifi" + ("; import CoreWLAN" if sys.platform == "darwin" else "")
        probe = subprocess.run([str(python), "-c", probe_code], capture_output=True)
        if probe.returncode or not marker.exists() or marker.read_text(encoding="utf-8") != requirements:
            print("Устанавливаю зависимости NetWatch…", file=sys.stderr, flush=True)
            subprocess.run([str(python), "-m", "pip", "install", "--disable-pip-version-check",
                            "-r", str(root / "requirements.txt")], check=True, stdout=sys.stderr)
            marker.write_text(requirements, encoding="utf-8")
        # Re-enter this script in the isolated interpreter. Its directory stays on
        # sys.path while relative --config/--log-file paths keep the caller's cwd.
        if Path(sys.prefix).resolve() == env.resolve():
            from netwatch.cli import main as launch
            return launch()
        return subprocess.call([str(python), str(Path(__file__).resolve()), *sys.argv[1:]])
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"Не удалось запустить NetWatch: {exc}\nПроверьте Python, модуль venv, доступ к PyPI и права на папку проекта.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
