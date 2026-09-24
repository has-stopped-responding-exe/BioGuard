import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from .realtime import feed

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
 consent INTEGER NOT NULL, consent_at TEXT NOT NULL, withdrawn_at TEXT,
 template_id TEXT, locked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 timestamp TEXT NOT NULL, device_id TEXT NOT NULL, ip TEXT NOT NULL,
 kind TEXT NOT NULL, result TEXT NOT NULL, reason TEXT NOT NULL, actor TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_window ON events(user_id,timestamp,id);
CREATE TABLE IF NOT EXISTS alerts (
 id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), rule TEXT NOT NULL,
 title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
 created_at TEXT NOT NULL, trigger_id INTEGER NOT NULL REFERENCES events(id)
);
CREATE TABLE IF NOT EXISTS evidence (
 alert_id INTEGER REFERENCES alerts(id), event_id INTEGER REFERENCES events(id),
 PRIMARY KEY(alert_id,event_id)
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
 user_id INTEGER REFERENCES users(id), alert_id INTEGER REFERENCES alerts(id), detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notes (
 id INTEGER PRIMARY KEY, alert_id INTEGER NOT NULL REFERENCES alerts(id),
 timestamp TEXT NOT NULL, actor TEXT NOT NULL, body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, role TEXT NOT NULL, expires_at REAL NOT NULL
);
PRAGMA user_version = 1;
'''

def path():
    return os.environ.get('BIOGUARD_DB', str(Path(__file__).with_name('bioguard.db')))

@contextmanager
def connection():
    db = sqlite3.connect(path(), timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        db.execute('BEGIN IMMEDIATE')
        yield db
        changed = db.total_changes > 0
        db.commit()
        if changed:
            feed.publish()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def initialize():
    with sqlite3.connect(path()) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript(SCHEMA)

def rows(db, sql, args=()):
    return [dict(r) for r in db.execute(sql, args).fetchall()]
