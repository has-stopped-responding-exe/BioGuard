import hashlib
import ipaddress
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from fastapi.responses import StreamingResponse
from .realtime import feed

from .db import connection, initialize, rows
from .detection import RULES, audit, record_event, utcnow
from .seed import enroll, seed

@asynccontextmanager
async def lifespan(app):
    initialize()
    with connection() as db:
        seed(db)
    yield

app = FastAPI(title='BioGuard API', version='1.0.0', lifespan=lifespan,
              description='Local synthetic-data security training sandbox. Demo sessions are not production authentication.')

@app.middleware('http')
async def headers(request: Request, call_next):
    origin = request.headers.get('origin')
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and origin and origin not in ('http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:8000', 'http://127.0.0.1:8000'):
        from fastapi.responses import JSONResponse
        return JSONResponse({'detail': 'Origin is not allowed'}, status_code=403)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return response

def identity(request: Request):
    token = request.cookies.get('bioguard_session', '')
    with connection() as db:
        session = db.execute('SELECT role FROM sessions WHERE token_hash=? AND expires_at>?',
                             (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
    if not session:
        raise HTTPException(401, 'Choose a demo role to start a session.')
    return session['role']

def admin(role=Depends(identity)):
    if role != 'admin':
        raise HTTPException(403, 'This action requires an admin session.')
    return role

@app.get('/api/stream')
def stream(request: Request, role=Depends(identity)):
    def messages():
        revision = feed.revision
        # Always resynchronize after connecting, including after server restart.
        yield f'retry: 2000\nevent: ready\ndata: {revision}\n\n'
        while True:
            current = feed.wait(revision)
            try:
                identity(request)
            except HTTPException:
                yield 'event: expired\ndata: {}\n\n'
                return
            if current != revision:
                revision = current
                yield f'event: change\ndata: {revision}\n\n'
            else:
                yield ': heartbeat\n\n'
    return StreamingResponse(messages(), media_type='text/event-stream',
                             headers={'X-Accel-Buffering': 'no', 'Cache-Control': 'no-cache'})

class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)

class SessionInput(Input):
    role: Literal['admin', 'analyst']

class UserInput(Input):
    name: str = Field(min_length=2, max_length=60, pattern=r'^[A-Za-z][A-Za-z .\-]*$')
    consent: Literal[True]

class SimulationInput(Input):
    user_id: int = Field(gt=0)
    device_id: str = Field(min_length=2, max_length=48, pattern=r'^[A-Za-z0-9_\-]+$')
    ip: str
    result: Literal['success', 'failure']

    @field_validator('ip')
    @classmethod
    def synthetic_ip(cls, value):
        ip = ipaddress.ip_address(value)
        if not any(ip in ipaddress.ip_network(net) for net in ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']):
            raise ValueError('Use a synthetic documentation IP: 192.0.2.x, 198.51.100.x, or 203.0.113.x')
        return str(ip)

class ScenarioInput(Input):
    kind: Literal['normal', 'failures', 'suspicious', 'unauthorized']

class LockInput(Input):
    locked: bool

class NoteInput(Input):
    body: str = Field(min_length=1, max_length=2000)

def user_exists(db, uid):
    user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not user:
        raise HTTPException(404, 'Test account not found.')
    return user

def alert_exists(db, aid):
    alert = db.execute('SELECT a.*,u.name FROM alerts a JOIN users u ON u.id=a.user_id WHERE a.id=?', (aid,)).fetchone()
    if not alert:
        raise HTTPException(404, 'Alert not found.')
    return dict(alert)

@app.get('/api/health')
def health():
    return {'status': 'ok', 'mode': 'synthetic sandbox'}

@app.post('/api/session')
def login(body: SessionInput, response: Response):
    token = secrets.token_urlsafe(32)
    with connection() as db:
        db.execute('DELETE FROM sessions WHERE expires_at<?', (time.time(),))
        db.execute('INSERT INTO sessions VALUES(?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), body.role, time.time()+28800))
        audit(db, body.role, 'Demo session started', detail='Local training session; explicit role selection.')
    response.set_cookie('bioguard_session', token, httponly=True, samesite='strict', max_age=28800)
    return {'role': body.role}

@app.get('/api/session')
def session(role=Depends(identity)):
    return {'role': role}

@app.delete('/api/session')
def logout(request: Request, response: Response, role=Depends(identity)):
    token = request.cookies.get('bioguard_session', '')
    with connection() as db:
        db.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),))
        audit(db, role, 'Demo session ended')
    response.delete_cookie('bioguard_session')
    return {'ok': True}

@app.get('/api/snapshot')
def snapshot(role=Depends(identity)):
    with connection() as db:
        users = rows(db, 'SELECT id,name,email,consent,consent_at,withdrawn_at,locked,created_at,template_id IS NOT NULL AS has_template FROM users ORDER BY id DESC')
        alerts = rows(db, 'SELECT a.*,u.name FROM alerts a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500')
        events = rows(db, 'SELECT e.*,u.name FROM events e JOIN users u ON u.id=e.user_id ORDER BY e.timestamp DESC,e.id DESC LIMIT 500')
        audits = rows(db, 'SELECT a.*,u.name FROM audit a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500')
        stats = dict(db.execute("SELECT COUNT(*) AS total_events,COALESCE(SUM(result='success'),0) AS successes,COALESCE(SUM(result='failure'),0) AS failures FROM events").fetchone())
        stats.update(dict(db.execute("SELECT COUNT(*) AS open_alerts,COUNT(DISTINCT user_id) AS affected_accounts FROM alerts WHERE status='open'").fetchone()))
        stats['severities'] = {r['severity']: r['n'] for r in db.execute("SELECT severity,COUNT(*) n FROM alerts WHERE status='open' GROUP BY severity")}
        cutoff = (datetime.now(timezone.utc)-timedelta(hours=24)).isoformat()
        activity = rows(db, "SELECT substr(timestamp,1,13) AS hour,COUNT(*) AS total,SUM(result IN ('failure','denied')) AS failed FROM events WHERE timestamp>=? GROUP BY hour ORDER BY hour", (cutoff,))
    return {'users': users, 'alerts': alerts, 'events': events, 'audit': audits, 'stats': stats, 'activity': activity,
            'rules': [{'id': k, 'title': v[0], 'severity': v[1], 'description': v[2]} for k,v in RULES.items()], 'list_limit': 500}

@app.post('/api/users', status_code=201)
def create_user(body: UserInput, role=Depends(admin)):
    with connection() as db:
        uid = enroll(db, body.name, role)
    return {'id': uid, 'message': 'Synthetic account enrolled with explicit consent.'}

@app.post('/api/simulations', status_code=201)
def simulate(body: SimulationInput, role=Depends(identity)):
    with connection() as db:
        user_exists(db, body.user_id)
        result = record_event(db, **body.model_dump(), actor=role)
        audit(db, role, 'Login simulated', body.user_id, detail=f"Event #{result['event_id']}: {result['result']}")
    return result

@app.post('/api/scenarios', status_code=201)
def scenario(body: ScenarioInput, role=Depends(admin)):
    with connection() as db:
        now = datetime.now(timezone.utc)
        uid = enroll(db, f'Demo {body.kind.title()} {secrets.choice(["Orion", "Vega", "Atlas", "Nova"])}', role,
                     timestamp=(now-timedelta(minutes=16)).isoformat(timespec='microseconds'))
        # Establish a known device through real historical events for isolated, repeatable demos.
        baseline = (now-timedelta(minutes=15)).isoformat(timespec='microseconds')
        initial = record_event(db, uid, 'WS-DEMO', '192.0.2.50', 'success', role, timestamp=baseline)
        for aid in initial['alert_ids']:
            db.execute("UPDATE alerts SET status='acknowledged' WHERE id=?", (aid,))
            audit(db, role, 'Alert acknowledged', uid, aid, 'Scenario baseline workstation reviewed.')
        ids = []
        if body.kind in ('failures', 'suspicious'):
            for index in range(5):
                ids += record_event(db, uid, 'UNKNOWN-7F2', '198.51.100.42', 'failure', role,
                                    timestamp=(now-timedelta(minutes=5-index)).isoformat(timespec='microseconds'))['alert_ids']
        if body.kind == 'suspicious':
            ids += record_event(db, uid, 'UNKNOWN-7F2', '198.51.100.42', 'success', role)['alert_ids']
        elif body.kind == 'normal':
            record_event(db, uid, 'WS-DEMO', '192.0.2.50', 'success', role)
        elif body.kind == 'unauthorized':
            ids += record_event(db, uid, 'API-CLIENT-09', '203.0.113.19', 'denied', 'analyst (simulated)', kind='template_access', reason='Role analyst is not authorized to read templates')['alert_ids']
        audit(db, role, 'Demo scenario executed', uid, detail=body.kind)
    return {'user_id': uid, 'alert_ids': ids, 'kind': body.kind}

@app.get('/api/alerts/{aid}')
def investigation(aid: int, role=Depends(identity)):
    with connection() as db:
        alert = alert_exists(db, aid)
        evidence = rows(db, 'SELECT e.* FROM evidence v JOIN events e ON v.event_id=e.id WHERE v.alert_id=? ORDER BY e.timestamp,e.id', (aid,))
        timeline = rows(db, 'SELECT * FROM events WHERE user_id=? ORDER BY timestamp,id', (alert['user_id'],))
        notes = rows(db, 'SELECT * FROM notes WHERE alert_id=? ORDER BY id', (aid,))
        audits = rows(db, 'SELECT * FROM audit WHERE user_id=? OR alert_id=? ORDER BY timestamp,id', (alert['user_id'], aid))
    return {'alert': alert, 'evidence': evidence, 'timeline': timeline, 'notes': notes, 'audit': audits}

@app.post('/api/alerts/{aid}/acknowledge')
def acknowledge(aid: int, role=Depends(admin)):
    with connection() as db:
        alert = alert_exists(db, aid)
        if alert['status'] == 'open':
            db.execute("UPDATE alerts SET status='acknowledged' WHERE id=?", (aid,))
            audit(db, role, 'Alert acknowledged', alert['user_id'], aid, 'Investigation accepted by administrator.')
    return {'ok': True}

@app.post('/api/alerts/{aid}/notes', status_code=201)
def note(aid: int, body: NoteInput, role=Depends(admin)):
    with connection() as db:
        alert = alert_exists(db, aid)
        db.execute('INSERT INTO notes(alert_id,timestamp,actor,body) VALUES(?,?,?,?)', (aid, utcnow(), role, body.body))
        audit(db, role, 'Investigation note added', alert['user_id'], aid, body.body)
    return {'ok': True}

@app.patch('/api/users/{uid}/lock')
def lock(uid: int, body: LockInput, role=Depends(admin)):
    with connection() as db:
        user = user_exists(db, uid)
        if bool(user['locked']) != body.locked:
            db.execute('UPDATE users SET locked=? WHERE id=?', (body.locked, uid))
            audit(db, role, 'Account locked' if body.locked else 'Account unlocked', uid)
    return {'ok': True}

@app.post('/api/users/{uid}/withdraw')
def withdraw(uid: int, role=Depends(admin)):
    with connection() as db:
        user = user_exists(db, uid)
        if user['consent']:
            db.execute('UPDATE users SET consent=0,withdrawn_at=? WHERE id=?', (utcnow(), uid))
            audit(db, role, 'Consent withdrawn', uid, detail='Authentication and template reads blocked. Template deletion is a separate explicit control.')
    return {'ok': True}

@app.delete('/api/users/{uid}/template')
def delete_template(uid: int, role=Depends(admin)):
    with connection() as db:
        user = user_exists(db, uid)
        if user['template_id']:
            db.execute('UPDATE users SET template_id=NULL WHERE id=?', (uid,))
            audit(db, role, 'Synthetic template deleted', uid, detail='Template ID removed. Historical security evidence retained.')
    return {'ok': True}

@app.post('/api/users/{uid}/template-access')
def template_access(uid: int, role=Depends(identity)):
    with connection() as db:
        user = user_exists(db, uid)
        allowed = role == 'admin' and user['consent'] and user['template_id']
        reason = 'Authorized admin read' if allowed else ('Admin role required' if role != 'admin' else 'Consent withdrawn or template deleted')
        result = record_event(db, uid, 'SOC-CONSOLE', '192.0.2.1', 'success' if allowed else 'denied', role, kind='template_access', reason=reason)
        audit(db, role, 'Template access allowed' if allowed else 'Template access denied', uid, detail=reason)
        template = user['template_id'] if allowed else None
    # Commit denied evidence before returning an error.
    if not allowed:
        raise HTTPException(403, reason + '; event and alert recorded.')
    return {'template_id': template, **result}

@app.get('/api/enrichment/{ip}')
def enrichment(ip: str, role=Depends(identity)):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(422, 'Enter a valid public IPv4 address.')
    if address.version != 4 or not address.is_global:
        return {'status': 'synthetic', 'message': 'Private and synthetic IPs are never sent to external services.', 'ip': ip}
    try:
        result = httpx.get(f'https://internetdb.shodan.io/{address}', timeout=6, follow_redirects=False)
        if result.status_code == 404:
            return {'status': 'empty', 'message': 'No InternetDB observations for this IP.', 'ip': ip}
        result.raise_for_status()
        data = result.json()
        if not isinstance(data, dict):
            raise ValueError('Invalid upstream response')
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, 'Shodan InternetDB is unavailable. Try again later; detection remains operational.')
    with connection() as db:
        audit(db, role, 'OSINT lookup', detail=f'Public IP {address} sent to Shodan InternetDB; no account or biometric data sent.')
    return {'status': 'ok', 'source': 'Shodan InternetDB', 'ip': ip, **{key: data.get(key, []) for key in ('ports', 'hostnames', 'tags', 'vulns')}}
