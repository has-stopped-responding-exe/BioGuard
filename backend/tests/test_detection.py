from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from backend import db
from backend.detection import record_event
from backend.main import app
from backend.seed import enroll

@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.setenv('BIOGUARD_DB', str(tmp_path / 'test.db'))
    db.initialize()
    with db.connection() as conn:
        uid = enroll(conn, 'Test Identity')
    return uid

def stamp(minutes=0):
    return (datetime(2026, 1, 1, 12, tzinfo=timezone.utc)+timedelta(minutes=minutes)).isoformat(timespec='microseconds')

def event(conn, uid, result='failure', minute=0, device='TEST-1'):
    return record_event(conn, uid, device, '192.0.2.1', result, timestamp=stamp(minute))

def rules(conn):
    return [r['rule'] for r in conn.execute('SELECT rule FROM alerts ORDER BY id')]

def test_five_failures_exact_boundary_and_evidence(database):
    with db.connection() as conn:
        for minute in [0, 2, 4, 6]:
            event(conn, database, minute=minute)
        assert 'BG-001' not in rules(conn)
        out = event(conn, database, minute=10)
        assert rules(conn) == ['BG-001']
        assert conn.execute('SELECT COUNT(*) FROM evidence WHERE alert_id=?', (out['alert_ids'][0],)).fetchone()[0] == 5

def test_old_failures_excluded(database):
    with db.connection() as conn:
        for minute in [0, 2, 4, 6, 10.01]:
            event(conn, database, minute=minute)
        assert 'BG-001' not in rules(conn)

def test_burst_deduplication(database):
    with db.connection() as conn:
        for _ in range(9):
            event(conn, database)
        assert rules(conn).count('BG-001') == 1

def test_five_failures_can_span_success(database):
    with db.connection() as conn:
        for _ in range(3):
            event(conn, database)
        event(conn, database, 'success')
        for _ in range(2):
            event(conn, database)
        assert 'BG-001' in rules(conn)

def test_success_after_three_failures(database):
    with db.connection() as conn:
        for _ in range(3):
            event(conn, database)
        event(conn, database, 'success')
        assert set(rules(conn)) == {'BG-002', 'BG-003'}
        aid = conn.execute("SELECT id FROM alerts WHERE rule='BG-002'").fetchone()[0]
        assert conn.execute('SELECT COUNT(*) FROM evidence WHERE alert_id=?', (aid,)).fetchone()[0] == 4
        event(conn, database, 'success')
        assert rules(conn).count('BG-002') == 1

def test_two_failures_not_suspicious_and_new_device_only_once(database):
    with db.connection() as conn:
        event(conn, database)
        event(conn, database)
        event(conn, database, 'success')
        event(conn, database, 'success')
        assert rules(conn) == ['BG-003']
        event(conn, database, 'success', device='OTHER')
        assert rules(conn) == ['BG-003', 'BG-003']

def test_account_isolation(database):
    with db.connection() as conn:
        other = enroll(conn, 'Another Identity')
        for uid in [database, other, database, other, database]:
            event(conn, uid)
        assert rules(conn) == []

def test_denied_template_access(database):
    with db.connection() as conn:
        out = record_event(conn, database, 'API', '192.0.2.1', 'denied', 'analyst', 'template_access', reason='Role denied')
        assert rules(conn) == ['BG-004']
        assert conn.execute('SELECT event_id FROM evidence').fetchone()[0] == out['event_id']

@pytest.fixture
def client(database):
    with TestClient(app) as client:
        client.post('/api/session', json={'role':'admin'})
        yield client

def test_complete_interview_workflow(client):
    scenario = client.post('/api/scenarios', json={'kind':'suspicious'}).json()
    assert len(scenario['alert_ids']) == 3
    aid = scenario['alert_ids'][1]
    investigation = client.get(f'/api/alerts/{aid}').json()
    assert investigation['alert']['rule'] == 'BG-002'
    assert len(investigation['evidence']) == 6
    assert client.post(f'/api/alerts/{aid}/acknowledge').status_code == 200
    uid = scenario['user_id']
    assert client.patch(f'/api/users/{uid}/lock', json={'locked':True}).status_code == 200
    assert client.post(f'/api/alerts/{aid}/notes', json={'body':'Contained after reviewing evidence.'}).status_code == 201
    result = client.post('/api/simulations', json={'user_id':uid,'device_id':'WS-DEMO','ip':'192.0.2.10','result':'success'}).json()
    assert result['result'] == 'failure'
    assert 'locked' in result['reason']
    detail = client.get(f'/api/alerts/{aid}').json()
    assert detail['alert']['status'] == 'acknowledged'
    assert detail['notes'][0]['body'] == 'Contained after reviewing evidence.'
    actions = {r['action'] for r in detail['audit']}
    assert {'Alert acknowledged','Account locked','Investigation note added'} <= actions
    assert client.patch(f'/api/users/{uid}/lock', json={'locked':False}).status_code == 200

def test_consent_template_deletion_and_rbac(client, database):
    uid = database
    assert client.post(f'/api/users/{uid}/template-access').json()['template_id'].startswith('syn_')
    assert all('template_id' not in u for u in client.get('/api/snapshot').json()['users'])
    client.post('/api/session', json={'role':'analyst'})
    assert client.patch(f'/api/users/{uid}/lock', json={'locked':True}).status_code == 403
    assert client.delete(f'/api/users/{uid}/template').status_code == 403
    assert client.post(f'/api/users/{uid}/template-access').status_code == 403
    snapshot = client.get('/api/snapshot').json()
    assert snapshot['alerts'][0]['rule'] == 'BG-004'
    assert snapshot['events'][0]['result'] == 'denied'
    client.post('/api/session', json={'role':'admin'})
    assert client.post(f'/api/users/{uid}/withdraw').status_code == 200
    assert client.post(f'/api/users/{uid}/template-access').status_code == 403
    event = client.post('/api/simulations', json={'user_id':uid,'device_id':'WS-1','ip':'192.0.2.10','result':'success'}).json()
    assert event['result'] == 'failure' and 'Consent' in event['reason']
    assert client.delete(f'/api/users/{uid}/template').status_code == 200
    with db.connection() as conn:
        assert conn.execute('SELECT template_id FROM users WHERE id=?', (uid,)).fetchone()[0] is None

def test_validation_and_session(client):
    assert client.post('/api/users', json={'name':'Test Account','consent':False}).status_code == 422
    assert client.post('/api/users', json={'name':'Test Account','consent':True,'aadhaar':'123'}).status_code == 422
    assert client.post('/api/simulations', json={'user_id':1,'device_id':'WS-1','ip':'8.8.8.8','result':'success'}).status_code == 422
    assert client.get('/api/alerts/999999').status_code == 404
    assert client.post('/api/scenarios', json={'kind':'unknown'}).status_code == 422
    assert client.post('/api/session', json={'role':'admin'}, headers={'Origin':'https://untrusted.example'}).status_code == 403
    assert client.delete('/api/session').status_code == 200
    assert client.get('/api/snapshot').status_code == 401

@pytest.mark.parametrize('kind,expected', [('normal',0),('failures',1),('suspicious',3),('unauthorized',1)])
def test_scenarios_repeatable(client, kind, expected):
    first = client.post('/api/scenarios', json={'kind':kind}).json()
    client.patch(f"/api/users/{first['user_id']}/lock", json={'locked':True})
    second = client.post('/api/scenarios', json={'kind':kind}).json()
    assert first['user_id'] != second['user_id']
    assert len(first['alert_ids']) == len(second['alert_ids']) == expected

def test_enrichment_no_synthetic_egress(client, monkeypatch):
    def never(*args, **kwargs):
        raise AssertionError('Synthetic addresses must not leave the server')
    monkeypatch.setattr('backend.main.httpx.get', never)
    assert client.get('/api/enrichment/192.0.2.10').json()['status'] == 'synthetic'
    assert client.get('/api/enrichment/127.0.0.1').json()['status'] == 'synthetic'
    assert client.get('/api/enrichment/bad-ip').status_code == 422

def test_enrichment_success_and_failure(client, monkeypatch):
    import httpx
    monkeypatch.setattr('backend.main.httpx.get', lambda *args, **kwargs: httpx.Response(200, json={'ports':[443],'tags':['test'],'hostnames':[],'vulns':[]}, request=httpx.Request('GET','https://internetdb.shodan.io/8.8.8.8')))
    assert client.get('/api/enrichment/8.8.8.8').json()['ports'] == [443]
    def fail(*args, **kwargs):
        raise httpx.ConnectTimeout('upstream down')
    monkeypatch.setattr('backend.main.httpx.get', fail)
    assert client.get('/api/enrichment/8.8.8.8').status_code == 502
