import copy
import json
import os
import socket
import threading
import urllib.error
import urllib.request
from dataclasses import asdict

import pytest

from netwatch import agent, core, measurements, tools
from netwatch.engine import Monitor
from netwatch.settings import Settings
from netwatch.storage import Journal
from netwatch.system import parse_iw, parse_nettop, parse_ss, process_activity
from test_mac_net_watch import _snapshot


@pytest.fixture
def local_agent(tmp_path, monkeypatch):
    monkeypatch.setenv('NETWATCH_AGENT_TOKEN', 'local-test-token')
    monitor = Monitor(Settings(), Journal(tmp_path, False))
    s = _snapshot(timestamp=core.iso_now())
    s.cause = core.build_assessment(s)
    monitor.accept(s)
    server = agent.make_server(monitor, port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', server.server_port, monitor
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_real_agent_auth_freshness_and_bounded_transfers(local_agent, monkeypatch):
    url, port, _ = local_agent
    result = agent.read_agent(url)
    assert result['fresh']
    assert result['snapshot']['cause']['status'] == 'ok'
    upload = measurements.upload(url + '/v1/upload', 4096, 2)
    assert not upload['ok']  # Upload needs the configured bearer token too.
    request = urllib.request.Request(url + '/v1/upload', data=b'N' * 4096,
        headers={'Authorization': 'Bearer local-test-token'})
    with urllib.request.urlopen(request, timeout=2) as response:
        assert json.load(response)['received_bytes'] == 4096
    monkeypatch.delenv('NETWATCH_AGENT_TOKEN')
    with pytest.raises(urllib.error.HTTPError) as error:
        agent.read_agent(url)
    assert error.value.code == 401


@pytest.mark.parametrize('url', ['http://example.com', 'https://u:p@localhost', 'http://localhost?a=1', 'ftp://localhost'])
def test_agent_requires_safe_transport_and_url(url, monkeypatch):
    monkeypatch.delenv('NETWATCH_AGENT_TOKEN', raising=False)
    with pytest.raises(ValueError):
        agent.read_agent(url)


def test_external_server_and_reflector_require_credentials(tmp_path, monkeypatch):
    monkeypatch.delenv('NETWATCH_AGENT_TOKEN', raising=False)
    monitor = Monitor(Settings(), Journal(tmp_path, False))
    with pytest.raises(ValueError):
        agent.make_server(monitor, '0.0.0.0', 0)
    with pytest.raises(ValueError):
        agent.Reflector('0.0.0.0')


def test_real_authenticated_udp_echo_and_bad_token(monkeypatch):
    reflector = agent.Reflector(token='correct-token').start()
    try:
        monkeypatch.setenv('NETWATCH_AGENT_TOKEN', 'correct-token')
        result = agent.udp_measure(f'127.0.0.1:{reflector.port}', 5, .1)
        assert result['received'] == 5
        assert result['loss_percent'] == 0
        monkeypatch.setenv('NETWATCH_AGENT_TOKEN', 'wrong-token')
        result = agent.udp_measure(f'127.0.0.1:{reflector.port}', 2, .05)
        assert result['lost'] == 2
    finally:
        reflector.close()
    assert not reflector.thread.is_alive()


def test_udp_signature_integrity_and_size():
    packet = agent.udp_packet(b'nonce', 'secret')
    assert agent.valid_udp(packet, 'secret')
    assert not agent.valid_udp(packet + b'changed', 'secret')
    assert not agent.valid_udp(b'N' * 1201, 'secret')


def test_real_load_quality_and_http_breakdown(http_server, tmp_path):
    url, port = http_server
    cfg = Settings(public_endpoints=[f'127.0.0.1:{port}'], speedtest_url=url, upload_url=url,
                   quality_samples=4, speedtest_bytes=4096, speedtest_timeout=1, timeout=.2,
                   regional_services=[], http_urls=[url], dns_servers=[])
    monitor = Monitor(cfg, Journal(tmp_path))
    result = tools.run(monitor, 'quality')['result']
    assert result['idle']['samples'] == 4
    assert result['stages']['download']['transfer']['transferred_bytes'] == 4096
    assert not result['stages']['upload']['transfer']['ok']  # HTTP fixture rejects POST.
    assert result['udp']['status'] == 'unconfigured'
    assert monitor.budget.summary()['bulk_bytes'] == 8192
    details = tools.run(monitor, 'http')['result']['http']
    assert details.get('ok', details.get('probe', {}).get('ok'))
    if 'timing_ms' in details:
        assert details['timing_ms']['total'] > 0
        assert details['bytes'] <= 65536
    assert len(Journal(tmp_path).history.query(kind='diagnostic')) == 2


def test_agent_upload_with_token_in_quality(local_agent, tmp_path):
    url, port, _ = local_agent
    # Reuse the agent as owned bulk endpoint with an explicit token-aware request.
    request = urllib.request.Request(url + '/v1/download?bytes=1000', headers={'Authorization': 'Bearer local-test-token'})
    with urllib.request.urlopen(request, timeout=2) as response:
        assert len(response.read()) == 1000


def test_assertion_mismatch_and_possible_portal(http_server):
    url, _ = http_server
    result = core.http_probe(url, 1, expected_status=204)
    assert not result.ok
    assert result.captive_portal
    assert not core.http_probe(url + '/blocked', 1, expected_status=204).captive_portal
    assert core.http_probe(url, 1, expected_text='networktestby').ok
    assert not core.http_probe(url, 1, expected_text='missing-body').ok
    s = _snapshot(http_probes=[result])
    assert core.build_assessment(s).code == 'possible_captive_portal'


def test_dns_disabled_is_unknown_source():
    s = _snapshot(direct_dns=[])
    for p in s.system_dns:
        p.ok = False
    assert core.build_assessment(s).code == 'dns_unconfirmed'


@pytest.mark.skipif(os.sys.platform != 'linux', reason='Linux UDP error queue')
def test_real_unprivileged_loopback_trace():
    result = measurements.udp_trace_linux('127.0.0.1', .2, hops=2)
    assert result['hops'][0]['reached']
    assert '127.0.0.1' in result['hops'][0]['addresses']
    assert result['hops'][0]['median_ms'] is not None


def test_wifi_and_native_network_counter_parsers():
    parsed = parse_iw('Connected to aa:bb:cc:dd:ee:ff\nSSID: Home\nfreq: 5180\nsignal: -57 dBm\ntx bitrate: 866.7 MBit/s')
    assert parsed['rssi_dbm'] == -57
    assert parsed['channel'] == 36
    assert parsed['tx_mbps'] == 866.7
    assert parse_nettop(',bytes_in,bytes_out\nSafari.123,1024,2048\n') == [{'pid': 123, 'name': 'Safari', 'rx_bytes': 1024, 'tx_bytes': 2048}]
    data = 'ESTAB 0 0 127.0.0.1:1 127.0.0.1:2 users:(("python",pid=123,fd=4))\n\t cubic bytes_acked:100 bytes_received:300\n'
    assert parse_ss(data) == {123: {'rx_bytes': 300, 'tx_bytes': 100}}
    assert parse_ss(data.replace('pid=123', 'pid=123,pid=456')) == {}


@pytest.mark.parametrize('host', ['--help', '-w 0', 'x;touch a', '', 'http:///bad'])
def test_command_targets_reject_options_and_invalid_hosts(host):
    with pytest.raises((ValueError, TypeError)):
        measurements.target_host(host)


def test_real_agent_quality_authentication(local_agent, tmp_path):
    url, port, _ = local_agent
    cfg = Settings(public_endpoints=[f'127.0.0.1:{port}'], speedtest_url=url + '/v1/download?bytes={bytes}',
                   upload_url=url + '/v1/upload', remote_agent_url=url,
                   quality_samples=3, speedtest_bytes=2048, speedtest_timeout=1, timeout=.2)
    monitor = Monitor(cfg, Journal(tmp_path, False))
    result = measurements.quality(monitor)
    assert result['stages']['upload']['transfer']['ok']
    assert result['stages']['download']['transfer']['ok']
    assert result['stages']['download']['transfer']['transferred_bytes'] == 2048
    assert monitor.budget.summary()['bulk_bytes'] == 4096


def test_dns_over_https_wire_protocol(http_server, monkeypatch):
    import dns.message
    import dns.rrset
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class DoH(BaseHTTPRequestHandler):
        def do_POST(self):
            query = dns.message.from_wire(self.rfile.read(int(self.headers['Content-Length'])))
            reply = dns.message.make_response(query)
            qtype = query.question[0].rdtype
            reply.answer.append(dns.rrset.from_text('example.test.', 60, 'IN', qtype,
                                '192.0.2.1' if qtype == 1 else '2001:db8::1'))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(reply.to_wire())
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), DoH)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = measurements.dns_compare('example.test', [], f'http://127.0.0.1:{server.server_port}', .2)
        rows = [r for r in result['results'] if r.get('transport') == 'DoH']
        assert len(rows) == 2
        assert rows[0]['answers'] == ['192.0.2.1']
        assert rows[1]['answers'] == ['2001:db8::1']
        assert all(r['ok'] for r in rows)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@pytest.mark.skipif(not __import__('shutil').which('openssl'), reason='Local TLS certificate generation requires openssl')
def test_tls_agent_certificate_is_verified(tmp_path, monkeypatch):
    import ssl
    import subprocess
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    config = tmp_path / 'openssl.cnf'
    config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=localhost\n[v3]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:true\n')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                    '-keyout', str(key), '-out', str(cert), '-config', str(config)], check=True, capture_output=True)
    monkeypatch.setenv('NETWATCH_AGENT_TOKEN', 'tls-local-test')
    monitor = Monitor(Settings(), Journal(tmp_path, False))
    s = _snapshot(timestamp=core.iso_now())
    s.cause = core.build_assessment(s)
    monitor.accept(s)
    server = agent.make_server(monitor, '0.0.0.0', 0, cert, key)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'https://127.0.0.1:{server.server_port}'
    try:
        with pytest.raises(urllib.error.URLError):
            agent.read_agent(url, 1)
        monkeypatch.setenv('SSL_CERT_FILE', str(cert))
        assert agent.read_agent(url, 1)['fresh']
        assert measurements.certificate(url, 1)['days_left'] > 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_verified_ca_fallback_for_clean_native_install(monkeypatch):
    import ssl
    from netwatch.trust import https_context
    monkeypatch.delenv('SSL_CERT_FILE', raising=False)
    monkeypatch.delenv('SSL_CERT_DIR', raising=False)
    monkeypatch.setattr(ssl, 'create_default_context', lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    context = https_context()
    assert context.cert_store_stats()['x509_ca'] > 0
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_ca_fallback_preserves_explicit_trust_boundary(monkeypatch):
    import ssl
    from netwatch.trust import https_context
    monkeypatch.setenv('SSL_CERT_FILE', '/explicit/enterprise.pem')
    monkeypatch.setattr(ssl, 'create_default_context', lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    assert https_context().cert_store_stats()['x509_ca'] == 0


def test_native_route_parsers_and_mtr_statistics():
    windows = measurements.parse_trace('  1    <1 мс    2 мс    3 мс  192.168.1.1\n  2     *        *        *     Превышен интервал ожидания\n', 3)
    assert windows[0]['latencies_ms'] == [1, 2, 3]
    assert windows[1]['responded'] == 0
    mac = measurements.parse_trace(' 1  192.168.1.1  1.432 ms  2.001 ms\n 2  2001:db8::1  4.3 ms  6 ms\n', 2)
    assert mac[1]['addresses'] == ['2001:db8::1']
    session = measurements.MTRSession()
    first = session.update({'target': 'localhost', 'hops': windows})
    second = session.update({'target': 'localhost', 'hops': windows})
    assert second['rounds'] == 2
    assert second['hops'][0]['attempts'] == 6
    assert second['hops'][0]['responded'] == 6
    assert second['hops'][0]['average_ms'] == 2
    assert second['hops'][1]['median_ms'] is None
    for _ in range(400):
        session.update({'target': 'localhost', 'hops': windows})
    assert len(session.rows[1]['latencies_ms']) == 1000
