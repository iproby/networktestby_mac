"""Explicit user-owned background lifecycle; no automatic service installation."""
from __future__ import annotations

import json
import os
import platform
import plistlib
import subprocess
import sys
import time
from pathlib import Path
from contextlib import contextmanager

import psutil


def launcher():
    if getattr(sys, "frozen", False):
        return [sys.executable]
    source = Path(__file__).resolve().parents[1] / "run.py"
    return [sys.executable, str(source)] if source.exists() else [sys.executable, "-m", "netwatch"]


def process(directory):
    path = directory / "background.json"
    try:
        data = json.loads(path.read_text())
        p = psutil.Process(data["pid"])
        return p if abs(p.create_time() - data["created"]) < .01 and p.is_running() and p.status() != psutil.STATUS_ZOMBIE else None
    except (OSError, ValueError, KeyError, psutil.Error):
        return None


@contextmanager
def lifecycle_lock(directory):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / "background.lock").open("a+b") as handle:
        if os.name == "nt":
            import msvcrt
            if handle.seek(0, 2) == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def manage(action, directory, config):
    if action == "status":
        return _manage(action, directory, config)
    with lifecycle_lock(directory):
        return _manage(action, directory, config)


def _manage(action, directory, config):
    directory = directory.resolve()
    running = process(directory)
    if action == "status":
        return {"running": running is not None, "pid": running.pid if running else None, "log": str(directory / "background.log")}
    if action == "stop":
        if running:
            try:
                # Windows TerminateProcess does not forward signals to a frozen
                # one-file application's child. All descendants belong to this
                # verified NetWatch PID; stop them before the bootloader.
                if os.name == "nt":
                    for child in running.children(recursive=True):
                        try:
                            child.terminate()
                        except psutil.NoSuchProcess:
                            pass
                running.terminate()
            except psutil.NoSuchProcess:
                pass
            try:
                running.wait(timeout=10)
            except psutil.TimeoutExpired:
                return {"running": True, "reason": "Остановка запрошена; ожидается завершение сетевой операции"}
        (directory / "background.json").unlink(missing_ok=True)
        return {"running": False}
    if running:
        return {"running": True, "pid": running.pid, "note": "Уже запущен"}
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_path = directory / f"background-profile-{time.time_ns()}.json"
    config.save(config_path)
    with (directory / "background.log").open("ab") as output:
        command = launcher() + ["--plain", "--quiet", "--config", str(config_path), "--state-dir", str(directory)]
        options = {"start_new_session": True} if os.name != "nt" else {
            "creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS}
        child_environment = os.environ.copy()
        if getattr(sys, "frozen", False):
            child_environment["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output, env=child_environment, **options)
    created = psutil.Process(child.pid).create_time()
    (directory / "background.json").write_text(json.dumps({"pid": child.pid, "created": created}), encoding="utf-8")
    time.sleep(.2)
    if child.poll() is not None:
        (directory / "background.json").unlink(missing_ok=True)
        raise ValueError(f"Фоновый запуск завершился с кодом {child.returncode}; см. {directory / 'background.log'}")
    return {"running": True, "pid": child.pid, "log": str(directory / "background.log")}


def service_definition(command, directory, system=None):
    system = system or platform.system()
    command = command + ["--plain", "--quiet", "--state-dir", str(directory)]
    if system == "Darwin":
        return plistlib.dumps({"Label": "dev.iproby.netwatch", "ProgramArguments": command,
                              "RunAtLoad": True, "KeepAlive": True,
                              "StandardOutPath": str(directory / "service.log"), "StandardErrorPath": str(directory / "service.log")})
    if system == "Linux":
        def quote(value):
            return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$").replace("\n", "\\n") + '"'
        return ("[Unit]\nDescription=NetWatch background diagnostics\nAfter=network-online.target\n"
                "[Service]\nExecStart=" + " ".join(quote(v) for v in command) +
                "\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=default.target\n").encode()
    return subprocess.list2cmdline(command).encode("utf-8")


def service(action, directory, config):
    system = platform.system()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_path = directory / "service-profile.json"
    command = launcher() + ["--config", str(config_path.resolve())]
    if system == "Darwin":
        path = Path.home() / "Library" / "LaunchAgents" / "dev.iproby.netwatch.plist"
        domain = f"gui/{os.getuid()}"
        commands = {"install": ["launchctl", "bootstrap", domain, str(path)],
                    "stop": ["launchctl", "bootout", domain, str(path)],
                    "start": ["launchctl", "bootstrap", domain, str(path)],
                    "status": ["launchctl", "print", domain + "/dev.iproby.netwatch"],
                    "remove": ["launchctl", "bootout", domain, str(path)]}
    elif system == "Linux":
        path = Path.home() / ".config" / "systemd" / "user" / "netwatch.service"
        commands = {"install": ["systemctl", "--user", "enable", "--now", "netwatch.service"],
                    **{a: ["systemctl", "--user", a, "netwatch.service"] for a in ("start", "stop", "status")},
                    "remove": ["systemctl", "--user", "disable", "--now", "netwatch.service"]}
    elif system == "Windows":
        commands = {"install": ["schtasks.exe", "/Create", "/SC", "ONLOGON", "/TN", "NetWatch", "/RL", "LIMITED", "/TR", service_definition(command, directory, system).decode()],
                    "start": ["schtasks.exe", "/Run", "/TN", "NetWatch"], "stop": ["schtasks.exe", "/End", "/TN", "NetWatch"],
                    "status": ["schtasks.exe", "/Query", "/TN", "NetWatch"], "remove": ["schtasks.exe", "/Delete", "/TN", "NetWatch", "/F"]}
        path = None
    else:
        raise ValueError("Регистрация службы недоступна для этой ОС")
    created_config = created_definition = False
    try:
        if action == "install":
            if path and path.exists():
                raise ValueError("Описание службы уже существует; оно не изменено")
            config.save(config_path)
            created_config = True
            if path:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("xb") as output:
                    output.write(service_definition(command, directory, system))
                created_definition = True
                if system == "Linux":
                    subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, timeout=10, capture_output=True)
        result = subprocess.run(commands[action], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
    except (OSError, ValueError, subprocess.SubprocessError):
        if created_definition:
            path.unlink(missing_ok=True)
        if created_config:
            config_path.unlink(missing_ok=True)
        raise
    # A definition is retained when registration might have partially succeeded;
    # its output allows the user to inspect/remove the service safely.
    if action == "remove" and result.returncode == 0:
        if path:
            path.unlink(missing_ok=True)
        config_path.unlink(missing_ok=True)
    return {"exit_code": result.returncode, "output": result.stdout, "error": result.stderr, "definition": str(path) if path else "Task Scheduler / NetWatch"}
