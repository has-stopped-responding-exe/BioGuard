"""Commit notifications for the single-process SQLite demo server."""
from threading import Condition


class ChangeFeed:
    def __init__(self):
        self.condition = Condition()
        self.revision = 0

    def publish(self):
        with self.condition:
            self.revision += 1
            self.condition.notify_all()

    def wait(self, previous, timeout=10):
        with self.condition:
            self.condition.wait_for(lambda: self.revision != previous, timeout)
            return self.revision


feed = ChangeFeed()
