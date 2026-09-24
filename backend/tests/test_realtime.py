from concurrent.futures import ThreadPoolExecutor

import pytest
from backend.db import connection, initialize
from backend.realtime import ChangeFeed, feed


def test_subscribers_receive_committed_changes(tmp_path, monkeypatch):
    monkeypatch.setenv('BIOGUARD_DB', str(tmp_path / 'stream.db'))
    initialize()
    before = feed.revision
    with ThreadPoolExecutor(max_workers=2) as pool:
        receivers = [pool.submit(feed.wait, before, 2) for _ in range(2)]
        with connection() as db:
            db.execute("INSERT INTO sessions VALUES('test', 'admin', 0)")
            assert feed.revision == before
        assert all(r.result() > before for r in receivers)
    with connection() as db:
        assert db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 1


def test_rollbacks_and_reads_do_not_publish(tmp_path, monkeypatch):
    monkeypatch.setenv('BIOGUARD_DB', str(tmp_path / 'stream.db'))
    initialize()
    before = feed.revision
    with pytest.raises(ValueError):
        with connection() as db:
            db.execute("INSERT INTO sessions VALUES('test', 'admin', 0)")
            raise ValueError('Rollback')
    with connection() as db:
        assert db.execute('SELECT COUNT(*) FROM sessions').fetchone()[0] == 0
    assert feed.revision == before


def test_changes_are_not_lost_between_waits():
    broker = ChangeFeed()
    broker.publish()
    broker.publish()
    assert broker.wait(0, 0) == 2
    assert broker.wait(2, 0) == 2
