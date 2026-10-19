from collections import deque
from threading import RLock

class MemoryStore:
    def __init__(self):
        self.events = deque(maxlen=3000)
        self.alerts = deque(maxlen=1000)
        self.lock = RLock()
        self.simulator_running = True
        self.events_per_minute = 30

    def reset(self):
        with self.lock:
            self.events.clear()
            self.alerts.clear()
