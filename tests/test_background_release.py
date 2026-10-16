import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from netwatch import background
from netwatch.settings import Settings


ROOT = Path(__file__).resolve().parents[1]


def test_service_definitions_preserve_arguments(tmp_path):
    args = ['/path with space/python', '/app/run.py', '--config', '/home/user/my profile.json']
    mac = plistlib.loads(background.service_definition(args, tmp_path, 'Darwin'))
    assert mac['ProgramArguments'][:len(args)] == args
    assert '--quiet' in mac['ProgramArguments']
    linux = background.service_definition(['/path/$x%file'], tmp_path, 'Linux').decode()
    assert '$$x%%file' in linux
    assert 'Restart=on-failure' in linux
    windows = background.service_definition(args, tmp_path, 'Windows').decode()
    assert '"/path with space/python"' in windows


def test_background_actual_lifecycle(http_server, tmp_path):
    url, port = http_server
    cfg = Settings(public_endpoints=[f'127.0.0.1:{port}'], http_urls=[url],
                   dns_names=['localhost'], dns_servers=[], regional_services=[],
                   wifi_enabled=False, interval=.2, timeout=.1)
    try:
        result = background.manage('start', tmp_path, cfg)
        assert result['running']
        assert background.manage('status', tmp_path, cfg)['pid'] == result['pid']
        assert background.manage('start', tmp_path, cfg)['pid'] == result['pid']
        deadline = time.monotonic() + 15
        log = tmp_path / 'network-diagnostics.jsonl'
        while time.monotonic() < deadline and not log.exists():
            time.sleep(.1)
        assert log.exists(), (tmp_path / 'background.log').read_text()
        assert 'sample' in log.read_text()
    finally:
        background.manage('stop', tmp_path, cfg)
    assert not background.manage('status', tmp_path, cfg)['running']


def test_stale_pid_is_not_signalled(tmp_path):
    (tmp_path / 'background.json').write_text(json.dumps({'pid': os.getpid(), 'created': 0}))
    assert background.process(tmp_path) is None
    assert not background.manage('stop', tmp_path, Settings())['running']


@pytest.mark.skipif(os.name == 'nt', reason='POSIX native installer')
def test_native_installer_checksums_cache_and_rollback(tmp_path):
    root = tmp_path / 'install with spaces'
    shims = tmp_path / 'bin'
    shims.mkdir()
    payload = tmp_path / 'app'
    payload.write_text('#!/bin/sh\nprintf "native-one:%s\\n" "$*"\n')
    curl = shims / 'curl'
    curl.write_text('''#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in https:*) url="$1" ;; -o) shift; output="$1" ;; esac
  shift
done
case "$url" in
  *.sha256) if [ "$NETWATCH_TEST_BAD" = 1 ]; then printf '%064d  app\n' 0 > "$output"; else if command -v sha256sum >/dev/null; then sha256sum "$NETWATCH_TEST_PAYLOAD" > "$output"; else shasum -a 256 "$NETWATCH_TEST_PAYLOAD" > "$output"; fi; fi ;;
  *) cp "$NETWATCH_TEST_PAYLOAD" "$output" ;;
esac
''')
    curl.chmod(0o755)
    env = os.environ.copy()
    env.update(NETWATCH_INSTALL_DIR=str(root), NETWATCH_TEST_PAYLOAD=str(payload), PATH=str(shims) + os.pathsep + env['PATH'])
    env.pop('NETWATCH_ROLLBACK', None)
    for text in ('native-one', 'native-two'):
        payload.write_text('#!/bin/sh\nprintf "' + text + ':%s\\n" "$*"\n')
        result = subprocess.run(['bash', str(ROOT / 'install-native.sh'), '--once'], env=env, text=True, capture_output=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == text + ':--once'
    env['NETWATCH_ROLLBACK'] = '1'
    result = subprocess.run(['bash', str(ROOT / 'install-native.sh'), '--version'], env=env, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'native-one:--version'
    env.pop('NETWATCH_ROLLBACK')
    env['NETWATCH_TEST_BAD'] = '1'
    before = (root / 'native' / 'current').read_text()
    result = subprocess.run(['bash', str(ROOT / 'install-native.sh')], env=env, text=True, capture_output=True, timeout=10)
    assert result.returncode != 0
    assert 'SHA-256' in result.stderr
    assert (root / 'native' / 'current').read_text() == before


def test_parallel_background_start_has_one_owner(http_server, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    url, port = http_server
    cfg = Settings(public_endpoints=[f'127.0.0.1:{port}'], http_urls=[url],
                   dns_names=['localhost'], dns_servers=[], regional_services=[], interval=3600, timeout=.1)
    try:
        with ThreadPoolExecutor(2) as pool:
            first, second = list(pool.map(lambda _: background.manage('start', tmp_path, cfg), range(2)))
        assert first['pid'] == second['pid']
    finally:
        background.manage('stop', tmp_path, cfg)
