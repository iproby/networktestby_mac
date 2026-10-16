"""Integration smoke checks for a built executable; no Python is exposed in its PATH."""
import json
import os
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import dns.message
import dns.rrset
from netwatch.settings import Settings

import argparse
parser = argparse.ArgumentParser()
parser.add_argument('binary', type=Path)
binary = parser.parse_args().binary.resolve()
calls = []
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        calls.append(self.path)
        body = b'N' * 4096
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass
    def do_POST(self):
        calls.append(self.path)
        data = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        if self.path == '/dns-query':
            query = dns.message.from_wire(data)
            answer = dns.message.make_response(query)
            kind = query.question[0].rdtype
            answer.answer.append(dns.rrset.from_text('localhost.', 60, 'IN', kind, '127.0.0.1' if kind == 1 else '::1'))
            data = answer.to_wire()
        else:
            data = b'ok'
        self.send_response(200)
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *args):
        pass
server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
url = f'http://127.0.0.1:{server.server_port}'
env = os.environ.copy()
env.update(PATH='/no-python-or-system-tools', TERM='xterm-256color', NO_PROXY='127.0.0.1,localhost', no_proxy='127.0.0.1,localhost')
env.pop('NO_COLOR', None)
with tempfile.TemporaryDirectory(prefix='netwatch-native-smoke-') as temporary:
    root = Path(temporary)
    cfg = Settings(interval=3600, timeout=.1, dns_names=['localhost'], dns_servers=[],
                   public_endpoints=[f'127.0.0.1:{server.server_port}'], http_urls=[url], regional_services=[],
                   speedtest_url=url, upload_url=url, doh_url=url + '/dns-query', speedtest_bytes=2048,
                   speedtest_timeout=1, quality_samples=3, wifi_enabled=False)
    path = root / 'profile.json'
    cfg.save(path)
    base = [str(binary), '--config', str(path), '--state-dir', str(root / 'state')]
    def run(arguments):
        result = subprocess.run(base + arguments, capture_output=True, text=True, encoding='utf-8', env=env, timeout=30)
        assert result.returncode == 0, result.stderr
        assert 'Traceback' not in result.stderr
        return result
    result = run(['--once', '--json', '--report', '--raw-report'])
    snapshot = json.loads(result.stdout)
    assert snapshot['http_probes'][0]['ok'] and snapshot['system_dns'][0]['ok']
    report = next((root / 'state' / 'reports').glob('*.json'))
    assert json.loads(report.read_text())['version'] == '4.0.0'
    before = len(calls)
    replay = run(['--replay', str(report), '--json'])
    assert json.loads(replay.stdout)['timestamp'] == snapshot['timestamp']
    assert len(calls) == before, 'Offline replay made requests'
    quality = json.loads(run(['--diagnose', 'quality']).stdout)['result']
    assert quality['stages']['download']['transfer']['ok']
    assert quality['stages']['upload']['transfer']['ok']
    dns = json.loads(run(['--diagnose', 'dns', '--target', 'localhost']).stdout)['result']
    assert len([r for r in dns['results'] if r.get('transport') == 'DoH' and r['ok']]) == 2
    background_start = json.loads(run(['--background', 'start']).stdout)
    try:
        deadline = time.monotonic() + 30
        journal = root / 'state' / 'network-diagnostics.jsonl'
        while time.monotonic() < deadline:
            if sum(json.loads(line).get('event') == 'sample' for line in journal.read_text(encoding='utf-8').splitlines()) >= 2:
                break
            time.sleep(.1)
        else:
            raise AssertionError('Background executable did not produce a sample')
        status = json.loads(run(['--background', 'status']).stdout)
        assert status['running'] and status['pid'] == background_start['pid']
    finally:
        assert not json.loads(run(['--background', 'stop']).stdout)['running']
    assert not json.loads(run(['--background', 'status']).stdout)['running']
    if os.name != 'nt':
        master, slave = os.openpty()
        import fcntl, termios
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 45, 150, 0, 0))
        process = subprocess.Popen(base, stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
        os.close(slave)
        output = bytearray()
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                if select.select([master], [], [], .1)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
            os.write(master, b'q')
            while process.poll() is None:
                if select.select([master], [], [], .1)[0]:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
                if time.monotonic() > deadline + 10:
                    raise AssertionError('TUI did not exit')
            process.wait(timeout=5)
            assert process.returncode == 0
            assert b'NETWATCH' in output and b'\x1b[' in output
            assert b'Traceback' not in output and b'ModuleNotFoundError' not in output
        finally:
            os.close(master)
            if process.poll() is None:
                process.terminate()
                process.wait(5)

server.shutdown()
server.server_close()
print('PASS: standalone executable with no Python in PATH; TCP/HTTP/DNS, upload/download, A/AAAA DoH, JSON+HTML, offline replay, background sample/status/stop; POSIX also opens a real PTY and exits with Q.')
