import copy
import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import pytest

from netwatch import core
from netwatch.budget import Budget
from netwatch.engine import Monitor
from netwatch.history import History
from netwatch.insights import baseline, compare, network_id
from netwatch.notifications import AlertPolicy
from netwatch.reports import anonymize, load_report, render_html
from netwatch.settings import Settings
from netwatch.storage import Journal
from test_mac_net_watch import _snapshot


def sample(timestamp=None, down=False, latency=10):
    s = _snapshot(timestamp=timestamp or core.iso_now())
    s.network_id = 'test-network'
    s.cause = core.build_assessment(s) if not down else core.make_assessment('down', 'test', 'No connection', .5, ['observed'], [])
    for p in s.public_probes:
        p.latency_ms = latency
        p.outcome = 'connected'
    return s


def test_restart_restores_samples_and_closes_interrupted_incident(tmp_path):
    monitor = Monitor(Settings(), Journal(tmp_path))
    start = datetime.now(timezone.utc)
    for i, down in enumerate((False, True, True)):
        monitor.accept(sample((start + timedelta(seconds=i * 5)).isoformat(), down))
    restored = Monitor(Settings(), Journal(tmp_path))
    assert len(restored.history) == 3
    assert len(restored.incidents) == 1
    assert restored.incidents[0]['interrupted']
    assert restored.incidents[0]['samples'] == 2
    assert restored.incidents[0]['ended_at'] == restored.history[-1].timestamp
    assert restored.active_incident is None
    assert len(Journal(tmp_path).history.context(restored.incidents[0])) == 3
    assert len(Journal(tmp_path).history.query(network='another-network')) == 0


def test_time_range_retention_and_usage(tmp_path):
    history = History(tmp_path / 'history.db', days=1, max_bytes=100000)
    history.append({'event': 'sample', 'snapshot': {'timestamp': '2026-01-01T00:00:00+00:00'}})
    for i in range(99):
        history.append({'event': 'traffic', 'timestamp': '2026-01-03T01:00:00+00:00', 'payload_bytes': 5, 'bulk_bytes': 3, 'control_requests': 1})
    assert history.query() == []
    assert history.usage('2026-01-03') == {'payload_bytes': 495, 'bulk_bytes': 297, 'control_requests': 99}
    assert history.query(kind='traffic', until='2026-01-02') == []
    assert len(history.query(kind='traffic', since='2026-01-03', limit=8)) == 8


def test_payload_retention_bound(tmp_path):
    history = History(tmp_path / 'history.db', max_bytes=200)
    for i in range(100):
        history.append({'event': 'sample', 'index': i})
    with history.connect() as db:
        assert db.execute('SELECT coalesce(sum(length(payload)),0) FROM events').fetchone()[0] <= 200


def test_sleep_gap_closes_incident_at_last_observation(tmp_path):
    monitor = Monitor(Settings(interval=1), Journal(tmp_path, False))
    monitor.accept(sample('2026-01-01T12:00:00+00:00', True))
    monitor.accept(sample('2026-01-01T13:00:00+00:00', True))
    assert monitor.incidents[0]['ended_at'] == '2026-01-01T12:00:00+00:00'
    assert monitor.incidents[0]['interrupted']
    assert len(monitor.incidents) == 2
    assert 'неизвестна' in monitor.history[-1].observations[0]


def test_baseline_learning_anomaly_and_network_isolation(tmp_path):
    monitor = Monitor(Settings(), Journal(tmp_path))
    for i in range(25):
        monitor.accept(sample(f'2026-01-01T12:00:{i:02}+00:00'))
    restored = Monitor(Settings(), Journal(tmp_path))
    restored.accept(sample('2026-01-01T12:00:30+00:00', latency=150))
    assert restored.history[-1].baseline['status'] == 'anomaly'
    assert restored.history[-1].baseline['samples'] == 25
    other = sample('2026-01-01T12:00:31+00:00', latency=150)
    other.network_id = 'another-network'
    restored.accept(other)
    assert other.baseline['status'] == 'learning'
    assert other.baseline['samples'] == 0
    assert network_id(other) == network_id(copy.deepcopy(other))


def test_alert_hysteresis_and_timezone_maintenance():
    settings = Settings(notify_after=3, recover_after=2)
    policy = AlertPolicy()
    assert policy.update(sample(down=True), settings) is None
    assert policy.update(sample(down=True), settings) is None
    assert policy.update(sample(down=True), settings)[0].endswith('связью')
    assert policy.update(sample(down=True), settings) is None
    assert policy.update(sample(), settings) is None
    assert policy.update(sample(), settings)[0].endswith('восстановлена')
    settings.maintenance_until = '2026-01-01T14:30:00+03:00'
    assert policy.update(sample('2026-01-01T11:15:00+00:00', True), settings) is None
    assert policy.failed == 0
    policy.update(sample('2026-01-01T11:35:00+00:00', True), settings)
    assert policy.failed == 1


def test_budget_is_durable_and_limits_parallel_reservations(tmp_path):
    cfg = Settings(daily_budget_mb=1)
    budget = Budget(cfg, Journal(tmp_path))
    with budget.reserve(600000) as meter:
        with pytest.raises(ValueError, match='лимит'):
            with budget.reserve(500000):
                pass
        meter.update(bytes=550000, requests=1)
    restored = Budget(cfg, Journal(tmp_path))
    assert restored.summary()['bulk_bytes'] == 550000
    assert restored.summary()['payload_bytes'] == 550000
    with pytest.raises(ValueError):
        with restored.reserve(500000):
            pass
    with pytest.raises(RuntimeError):
        with restored.reserve(1000) as meter:
            meter.update(bytes=500, requests=1)
            raise RuntimeError('transfer interrupted')
    assert restored.summary()['reserved_bytes'] == 0
    assert Budget(cfg, Journal(tmp_path)).summary()['bulk_bytes'] == 550500


def test_budget_denies_bulk_when_history_unreadable(tmp_path, monkeypatch):
    journal = Journal(tmp_path)
    monkeypatch.setattr(journal.history, 'usage', lambda day: (_ for _ in ()).throw(sqlite3.OperationalError('unreadable')))
    budget = Budget(Settings(), journal)
    assert budget.summary()['storage_error'] == 'unreadable'
    with pytest.raises(ValueError, match='бюджет'):
        with budget.reserve(1000):
            pass


def test_no_log_creates_no_history_and_offline_has_no_side_effects(tmp_path, monkeypatch):
    monitor = Monitor(Settings(), Journal(tmp_path / 'state', False))
    monitor.accept(sample())
    assert not (tmp_path / 'state').exists()
    report = monitor.export()
    data = load_report(report)
    other = Monitor(Settings(), Journal(tmp_path / 'replay', False))
    other.load_offline(data)
    from netwatch.tools import run
    monkeypatch.setattr(core, 'tcp_probe', lambda *a: pytest.fail('offline network call'))
    for operation in (other.sample, other.measure_speed, lambda: run(other, 'quality')):
        with pytest.raises(ValueError):
            operation()
    assert len(other.history) == 1
    assert not (tmp_path / 'replay').exists()


def test_report_html_anonymization_and_incident_context(tmp_path):
    monitor = Monitor(Settings(), Journal(tmp_path))
    monitor.accept(sample(down=True))
    raw = asdict(monitor.history[-1])
    raw['wifi'] = {'ssid': 'PrivateWifi', 'bssid': 'aa:bb:cc:dd:ee:ff'}
    report = anonymize({'application': 'NetWatch', 'snapshots': [raw], 'incidents': [], 'token': 'secret',
        'error': 'https://user:password@example.test/path?key=secret#fragment 192.168.1.1 2001:db8::1 <script>alert(1)</script>'})
    text = json.dumps(report)
    for secret in ('PrivateWifi', 'aa:bb:cc:dd:ee:ff', 'password', 'secret', '192.168.1.1', '2001:db8::1'):
        assert secret not in text
    page = render_html(report)
    assert '<script>' not in page
    assert '<svg ' in page
    exported = monitor.export()
    assert exported.with_suffix('.html').exists()
    assert len(load_report(exported)['flight_recorder'][0]['snapshots']) == 1


@pytest.mark.parametrize('change', [lambda d: d.update(snapshots=[{}]), lambda d: d.update(incidents=[{}]),
                                    lambda d: d.update(total_samples=-1), lambda d: d.update(diagnostics={})])
def test_malformed_report_is_rejected(tmp_path, change):
    data = {'application': 'NetWatch', 'snapshots': [asdict(sample())]}
    change(data)
    path = tmp_path / 'report.json'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_report(path)


def test_comparison_uses_common_targets_and_latency_delta():
    a, b = asdict(sample(latency=10)), asdict(sample(latency=35))
    result = compare(a, b)
    assert result['same_targets']
    assert result['latency_changes'][0]['delta_ms'] == 25
    b['public_probes'] = []
    assert not compare(a, b)['same_targets']


def test_budget_serializes_multiple_instances(tmp_path):
    first = Budget(Settings(daily_budget_mb=1), Journal(tmp_path))
    second = Budget(Settings(daily_budget_mb=1), Journal(tmp_path))
    with first.reserve(600000) as meter:
        with pytest.raises(ValueError):
            with second.reserve(500000):
                pytest.fail('cross-process reservation was ignored')
        meter.update(bytes=300000, requests=1)
    with second.reserve(500000) as meter:
        meter.update(bytes=500000, requests=1)
    assert Budget(Settings(), Journal(tmp_path)).summary()['bulk_bytes'] == 800000


def test_anonymization_includes_urls_used_as_dictionary_keys():
    data = anonymize({'settings': {'http_assertions': {'http://192.168.20.1/?key=private': {'status': 204}}},
                      'address': 'fe80::1%en0'})
    text = json.dumps(data)
    assert '192.168.20.1' not in text
    assert 'private' not in text
    assert 'fe80::1' not in text
    assert '<IP-' in text


def test_long_incident_preserves_before_and_after_with_bounded_context(tmp_path):
    history = History(tmp_path / 'history.db')
    start = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
    for offset in range(-5, 106):
        history.append({'event': 'sample', 'snapshot': {'timestamp': (start + timedelta(seconds=offset)).isoformat()}})
    context = history.context({'started_at': start.isoformat(), 'ended_at': (start + timedelta(seconds=100)).isoformat()}, limit=8)
    assert len(context) <= 8
    assert context[0]['timestamp'] < start.isoformat()
    assert context[-1]['timestamp'] > (start + timedelta(seconds=100)).isoformat()


def test_corrupted_archive_does_not_crash_live_monitor(tmp_path):
    history = History(tmp_path / 'history.sqlite3')
    history.append({'event': 'sample', 'snapshot': asdict(sample())})
    with history.connect() as db:
        db.execute('UPDATE events SET payload=?', (b'corrupted',))
    monitor = Monitor(Settings(), Journal(tmp_path))
    assert 'Повреждена' in monitor.storage_warning
    monitor.accept(sample())
    assert monitor.total == 1
    assert monitor.storage_warning
    assert monitor.export().exists()
