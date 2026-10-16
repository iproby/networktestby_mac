#!/usr/bin/env python3
"""Download a complete GitHub snapshot, cache it, then launch NetWatch."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

REPOSITORY = "iproby/networktestby_mac"
MAX_ARCHIVE = 50_000_000
REQUIRED = ("run.py", "requirements.txt", "pyproject.toml", "netwatch/__init__.py")


class InstallError(Exception):
    pass


def install_directory() -> Path:
    override = os.environ.get("NETWATCH_INSTALL_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share")))
    return base / "NetWatch"


def archive_url(ref: str) -> str:
    if not ref or not re.fullmatch(r"[A-Za-z0-9._/-]+", ref) or ref.startswith("/") or ".." in ref:
        raise InstallError("NETWATCH_REF должен содержать имя ветки, тег или SHA коммита.")
    return f"https://codeload.github.com/{REPOSITORY}/zip/{urllib.parse.quote(ref, safe='/')}"


def download_archive(url: str, path: Path) -> str:
    digest = hashlib.sha256()
    request = urllib.request.Request(url, headers={"User-Agent": "NetWatch-Installer/4.0"})
    size = 0
    # urllib uses the platform's normal TLS verification; never bypass it.
    with urllib.request.urlopen(request, timeout=30) as response, path.open("xb") as handle:
        while True:
            block = response.read(64 * 1024)
            if not block:
                break
            size += len(block)
            if size > MAX_ARCHIVE:
                raise InstallError("Архив превышает допустимый размер 50 МБ.")
            digest.update(block)
            handle.write(block)
    return digest.hexdigest()


def unpack_archive(archive: Path, destination: Path) -> None:
    """Validate every path before writing; never materialize archive symlinks."""
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if not entries or len(entries) > 5000 or sum(i.file_size for i in entries) > MAX_ARCHIVE:
            raise InstallError("Пустой или слишком большой архив приложения.")
        roots = set()
        paths = set()
        validated = []
        for item in entries:
            path = PurePosixPath(item.filename)
            if (path.is_absolute() or not path.parts or ".." in path.parts or "\\" in item.filename
                    or any(":" in part for part in path.parts) or stat.S_ISLNK(item.external_attr >> 16)):
                raise InstallError("Архив содержит недопустимый путь или символическую ссылку.")
            roots.add(path.parts[0])
            if len(path.parts) == 1:
                if not item.is_dir():
                    raise InstallError("Не распознан корневой каталог GitHub-архива.")
                continue
            relative = Path(*path.parts[1:])
            if relative in paths:
                raise InstallError("В архиве повторяется путь файла.")
            paths.add(relative)
            validated.append((item, relative))
        if len(roots) != 1:
            raise InstallError("Ожидался один корневой каталог GitHub-архива.")
        destination.mkdir()
        for item, relative in validated:
            target = destination / relative
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(item) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
    if not all((destination / name).is_file() for name in REQUIRED):
        raise InstallError("В этой версии GitHub ещё нет полного NetWatch 4. Опубликуйте обновлённый код или выберите NETWATCH_REF.")


def is_installed(path: Path, digest: str) -> bool:
    marker = path / ".netwatch-install.json"
    try:
        return (all((path / name).is_file() for name in REQUIRED)
                and json.loads(marker.read_text(encoding="utf-8")).get("archive_sha256") == digest)
    except (OSError, ValueError, AttributeError):
        return False


def prepare(root: Path, ref: str) -> Path:
    url = archive_url(ref)
    versions = root / "versions"
    versions.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix=".download-", dir=versions) as temporary:
        temporary = Path(temporary)
        archive = temporary / "source.zip"
        print(f"NetWatch · загружаю {REPOSITORY} ({ref})…", file=sys.stderr, flush=True)
        digest = download_archive(url, archive)
        target = versions / digest
        if is_installed(target, digest):
            return target
        if target.exists():
            raise InstallError(f"Каталог {target} уже существует и не распознан. Он не изменён; выберите другой NETWATCH_INSTALL_DIR.")
        stage = temporary / "app"
        unpack_archive(archive, stage)
        (stage / ".netwatch-install.json").write_text(
            json.dumps({"repository": REPOSITORY, "ref": ref, "archive_sha256": digest}), encoding="utf-8")
        try:
            stage.rename(target)
        except OSError:
            # Two installers may download the same snapshot concurrently.
            if not is_installed(target, digest):
                raise
        return target


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if sys.version_info < (3, 9):
        print("NetWatch требует Python 3.9+. Установите Python с python.org.", file=sys.stderr)
        return 2
    try:
        source = prepare(install_directory(), os.environ.get("NETWATCH_REF") or "main")
        print(f"Запускаю NetWatch · {source}", file=sys.stderr, flush=True)
        return subprocess.call([sys.executable, str(source / "run.py"), *(sys.argv[1:] if argv is None else argv)])
    except (InstallError, OSError, urllib.error.URLError, zipfile.BadZipFile) as exc:
        print(f"Не удалось установить NetWatch: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
