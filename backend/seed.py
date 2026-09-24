import uuid
from datetime import datetime, timedelta, timezone
from .detection import record_event, audit, utcnow

def enroll(db, name, actor='admin', timestamp=None):
    stamp = timestamp or utcnow()
    uid = db.execute('INSERT INTO users(name,email,consent,consent_at,template_id,created_at) VALUES(?,?,1,?,?,?)',
                     (name, f'test-{uuid.uuid4().hex[:10]}@bioguard.test', stamp, 'syn_' + uuid.uuid4().hex, stamp)).lastrowid
    audit(db, actor, 'Account enrolled', uid, detail='Explicit consent granted for synthetic biometric simulation; policy v1.', timestamp=stamp)
    return uid

def seed(db):
    if db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
        return
    now = datetime.now(timezone.utc)
    names = ['Alex Morgan', 'Priya Shah', 'Jordan Lee', 'Sam Rivera', 'Taylor Chen', 'Riley Brooks', 'Casey Park', 'Jamie Wilson']
    for i, name in enumerate(names):
        uid = enroll(db, name, 'Seed service', timestamp=(now-timedelta(hours=25)).isoformat(timespec='microseconds'))
        for j in range(8):
            when = now - timedelta(hours=23-j*3, minutes=i*2)
            # Historical baseline still runs through the real detection engine.
            record_event(db, uid, f'WS-{100+i}', f'192.0.2.{10+i}', 'success', 'Seed service', timestamp=when.isoformat(timespec='microseconds'))
    db.execute("UPDATE alerts SET status='acknowledged'")
    for alert in db.execute('SELECT id,user_id FROM alerts').fetchall():
        audit(db, 'Seed service', 'Alert acknowledged', alert['user_id'], alert['id'], 'Reviewed initial enrolled workstation.')
    for j in range(5):
        record_event(db, 2, 'UNKNOWN-7F2', '198.51.100.42', 'failure', 'Seed service', timestamp=(now-timedelta(minutes=7-j)).isoformat(timespec='microseconds'))
    record_event(db, 2, 'UNKNOWN-7F2', '198.51.100.42', 'success', 'Seed service', timestamp=(now-timedelta(minutes=2)).isoformat(timespec='microseconds'))
    record_event(db, 4, 'API-CLIENT-09', '203.0.113.19', 'denied', 'analyst', kind='template_access', reason='Role analyst is not authorized to read templates', timestamp=(now-timedelta(minutes=1)).isoformat(timespec='microseconds'))
