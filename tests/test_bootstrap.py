import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import bootstrap

ROOT = Path(__file__).resolve().parents[1]
STUB = """import json, os, sys
print(json.dumps({'args': sys.argv[1:], 'cwd': os.getcwd(), 'tty': sys.stdin.isatty()}))
raise SystemExit(17 if '--fail' in sys.argv else 0)
"""


@pytest.fixture
def source_zip(tmp_path):
    archive = tmp_path / "snapshot.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        for name in bootstrap.REQUIRED:
            bundle.writestr("networktestby_mac-main/" + name, STUB if name == "run.py" else "# fixture\n")
    return archive


@pytest.fixture
def downloaded(monkeypatch, source_zip):
    def download(url, path):
        assert url.startswith("https://codeload.github.com/iproby/networktestby_mac/zip/")
        shutil.copyfile(source_zip, path)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(bootstrap, "download_archive", download)


def test_install_snapshot_reuses_cache_and_preserves_files(tmp_path, downloaded, monkeypatch):
    root = tmp_path / "Install with spaces"
    first = bootstrap.prepare(root, "main")
    sentinel = first / "user-file.txt"
    sentinel.write_text("keep me")
    def unexpected(*args):
        raise AssertionError("An installed snapshot should not be unpacked again")
    monkeypatch.setattr(bootstrap, "unpack_archive", unexpected)
    assert bootstrap.prepare(root, "main") == first
    assert sentinel.read_text() == "keep me"
    assert not list((root / "versions").glob(".download-*"))


def test_launch_forwards_arguments_cwd_and_exit_code(tmp_path, downloaded, monkeypatch, capfd):
    monkeypatch.setenv("NETWATCH_INSTALL_DIR", str(tmp_path / "installed"))
    monkeypatch.setenv("NETWATCH_REF", "main")
    caller = tmp_path / "Caller with spaces"
    caller.mkdir()
    monkeypatch.chdir(caller)
    assert bootstrap.main(["--config", "profile with spaces.json"]) == 0
    output = json.loads(capfd.readouterr().out)
    assert output["cwd"] == str(caller)
    assert output["args"] == ["--config", "profile with spaces.json"]
    assert bootstrap.main(["--fail"]) == 17


@pytest.mark.parametrize("member", ["repo/../escape", "/absolute/path", "repo/C:/escape", "repo/dir\\escape"])
def test_archive_path_traversal_is_rejected(tmp_path, member):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(member, "should not be written")
    destination = tmp_path / "app"
    with pytest.raises(bootstrap.InstallError):
        bootstrap.unpack_archive(archive, destination)
    assert not destination.exists()
    assert not (tmp_path / "escape").exists()


def test_archive_symlink_is_rejected(tmp_path):
    archive = tmp_path / "link.zip"
    link = zipfile.ZipInfo("repo/escape")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr(link, "/tmp")
    with pytest.raises(bootstrap.InstallError):
        bootstrap.unpack_archive(archive, tmp_path / "app")


def test_unpublished_application_is_reported(tmp_path, source_zip, downloaded, monkeypatch, capfd):
    with zipfile.ZipFile(source_zip, "w") as bundle:
        bundle.writestr("repo/README.md", "old version")
    monkeypatch.setenv("NETWATCH_INSTALL_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("NETWATCH_REF", "main")
    assert bootstrap.main([]) == 2
    assert "NetWatch 3" in capfd.readouterr().err
    assert not list((tmp_path / "cache" / "versions").glob(".download-*"))


@pytest.mark.parametrize("ref", ["../main", "bad?ref", "/main", "bad ref", ""])
def test_ref_validation(ref):
    with pytest.raises(bootstrap.InstallError):
        bootstrap.archive_url(ref)


def test_branch_ref_and_commit_are_supported():
    assert bootstrap.archive_url("refs/heads/codex/netwatch").endswith("/refs/heads/codex/netwatch")
    assert bootstrap.archive_url("a" * 40).endswith("/" + "a" * 40)


def test_network_failure_does_not_launch_or_leave_partial_files(tmp_path, monkeypatch, capfd):
    def fail(*args):
        raise OSError("download-failed")
    monkeypatch.setenv("NETWATCH_INSTALL_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("NETWATCH_REF", "main")
    monkeypatch.setattr(bootstrap, "download_archive", fail)
    assert bootstrap.main([]) == 2
    assert "download-failed" in capfd.readouterr().err
    assert not list((tmp_path / "cache" / "versions").iterdir())


@pytest.fixture
def shell_environment(tmp_path):
    shim = tmp_path / "bin"
    shim.mkdir()
    stub = tmp_path / "stub.py"
    stub.write_text(STUB, encoding="utf-8")
    curl = shim / "curl"
    curl.write_text('''#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    cp "$NETWATCH_TEST_BOOTSTRAP" "$2"
    exit 0
  fi
  shift
done
exit 2
''')
    curl.chmod(0o755)
    temporary = tmp_path / "temporary files"
    temporary.mkdir()
    task_env = os.environ.copy()
    task_env.update(PATH=str(shim) + os.pathsep + task_env["PATH"], NETWATCH_TEST_BOOTSTRAP=str(stub), TMPDIR=str(temporary))
    task_env.pop("NETWATCH_REF", None)
    return task_env, temporary


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell entry point")
def test_shell_installer_arguments_cleanup_and_failure_status(shell_environment):
    task_env, temporary = shell_environment
    result = subprocess.run(["bash", str(ROOT / "install.sh"), "--version"],
                            env=task_env, text=True, capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["args"] == ["--version"]
    assert not list(temporary.iterdir())
    result = subprocess.run(["bash", str(ROOT / "install.sh"), "--fail"],
                            env=task_env, text=True, capture_output=True, timeout=20)
    assert result.returncode == 17, result.stderr
    assert not list(temporary.iterdir())


@pytest.mark.skipif(os.name == "nt", reason="POSIX terminal pipe entry point")
def test_piped_installer_gives_application_the_terminal(shell_environment):
    import pty
    import select
    import shlex
    import time
    task_env, temporary = shell_environment
    command = f"cat {shlex.quote(str(ROOT / 'install.sh'))} | bash -s -- --version"
    pid, descriptor = pty.fork()
    if pid == 0:
        os.execvpe("bash", ["bash", "-c", command], task_env)
    output = bytearray()
    status = None
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if select.select([descriptor], [], [], .1)[0]:
                try:
                    output.extend(os.read(descriptor, 65536))
                except OSError:
                    break
            child, child_status = os.waitpid(pid, os.WNOHANG)
            if child:
                status = child_status
                break
        if status is None:
            child, child_status = os.waitpid(pid, os.WNOHANG)
            if child:
                status = child_status
        if status is None:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            pytest.fail("Installer did not finish")
        assert os.waitstatus_to_exitcode(status) == 0, output.decode(errors="replace")
        assert json.loads(output.decode().strip())["tty"] is True
        assert not list(temporary.iterdir())
    finally:
        os.close(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell entry point")
def test_powershell_entry_forwards_arguments(tmp_path):
    stub = tmp_path / "stub.py"
    stub.write_text(STUB, encoding="utf-8")
    task_env = os.environ.copy()
    task_env["NETWATCH_TEST_BOOTSTRAP"] = str(stub)
    task_env.pop("NETWATCH_REF", None)
    script = tmp_path / "test-install.ps1"
    install = str(ROOT / "install.ps1").replace("'", "''")
    script.write_text("""$ErrorActionPreference = 'Stop'
function Invoke-WebRequest {
    param([switch]$UseBasicParsing, [string]$Uri, [string]$OutFile)
    Copy-Item -LiteralPath $env:NETWATCH_TEST_BOOTSTRAP -Destination $OutFile
}
""" + f"& '{install}' --version\n", encoding="utf-8")
    result = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-File", str(script)],
                            env=task_env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["args"] == ["--version"]
