from datetime import datetime, timedelta, timezone

RULES = {
    'BG-001': ('Repeated authentication failures', 'high', 'Five failed logins within ten minutes, even with intervening successes. One alert at each threshold crossing.'),
    'BG-002': ('Success after repeated failures', 'critical', 'A successful login after at least three failures in ten minutes since the previous success.'),
    'BG-003': ('New device sign-in', 'medium', 'A successful login from a device without a previous successful login for this account.'),
    'BG-004': ('Unauthorized template access', 'high', 'A denied attempt to access a synthetic biometric template.'),
}

def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='microseconds')

def audit(db, actor, action, user_id=None, alert_id=None, detail='', timestamp=None):
    db.execute('INSERT INTO audit(timestamp,actor,action,user_id,alert_id,detail) VALUES(?,?,?,?,?,?)',
               (timestamp or utcnow(), actor, action, user_id, alert_id, detail))

def detect(db, event_id):
    e = db.execute('SELECT * FROM events WHERE id=?', (event_id,)).fetchone()
    cutoff = (datetime.fromisoformat(e['timestamp']) - timedelta(minutes=10)).isoformat(timespec='microseconds')
    recent = db.execute('SELECT * FROM events WHERE user_id=? AND kind=\'login\' AND timestamp>=? AND timestamp<=? AND id<? ORDER BY timestamp,id',
                        (e['user_id'], cutoff, e['timestamp'], event_id)).fetchall()
    failures = []
    for prior in recent:
        if prior['result'] == 'success':
            failures = []
        elif prior['result'] == 'failure':
            failures.append(prior['id'])
    fired = []
    if e['kind'] == 'login':
        window_failures = [p['id'] for p in recent if p['result'] == 'failure']
        if e['result'] == 'failure' and len(window_failures) == 4:
            fired.append(('BG-001', window_failures + [event_id]))
        if e['result'] == 'success':
            if len(failures) >= 3:
                fired.append(('BG-002', failures + [event_id]))
            known = db.execute("SELECT 1 FROM events WHERE user_id=? AND device_id=? AND kind='login' AND result='success' AND id<? LIMIT 1",
                               (e['user_id'], e['device_id'], event_id)).fetchone()
            if not known:
                fired.append(('BG-003', [event_id]))
    elif e['kind'] == 'template_access' and e['result'] == 'denied':
        fired.append(('BG-004', [event_id]))
    ids = []
    for rule, evidence in fired:
        title, severity, _ = RULES[rule]
        aid = db.execute('INSERT INTO alerts(user_id,rule,title,severity,created_at,trigger_id) VALUES(?,?,?,?,?,?)',
                         (e['user_id'], rule, title, severity, e['timestamp'], event_id)).lastrowid
        db.executemany('INSERT INTO evidence VALUES(?,?)', [(aid, x) for x in evidence])
        audit(db, 'Detection engine', 'Alert generated', e['user_id'], aid, rule, e['timestamp'])
        ids.append(aid)
    return ids

def record_event(db, user_id, device_id, ip, result, actor='admin', kind='login', timestamp=None, reason=None):
    user = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if user is None:
        raise ValueError('Account does not exist')
    if kind == 'login':
        if user['locked']:
            result, reason = 'failure', 'Account locked by administrator'
        elif not user['consent']:
            result, reason = 'failure', 'Consent withdrawn; authentication blocked'
        elif not user['template_id']:
            result, reason = 'failure', 'Synthetic template deleted; authentication blocked'
        else:
            reason = 'Synthetic template matched' if result == 'success' else 'Synthetic template mismatch'
    eid = db.execute('INSERT INTO events(user_id,timestamp,device_id,ip,kind,result,reason,actor) VALUES(?,?,?,?,?,?,?,?)',
                     (user_id, timestamp or utcnow(), device_id, ip, kind, result, reason, actor)).lastrowid
    alerts = detect(db, eid)
    return {'event_id': eid, 'alert_ids': alerts, 'result': result, 'reason': reason}
