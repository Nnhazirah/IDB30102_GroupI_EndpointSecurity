import subprocess
import threading
import time
import queue
from datetime import datetime

class SysmonCollector:
    
    def __init__(self, event_queue):
        self.event_queue = event_queue
        self.running = False
        self.thread = None
        
    def start_collection(self):
        self.running = True
        self.thread = threading.Thread(target=self._collect_events)
        self.thread.start()
        
    def stop_collection(self):
        self.running = False
        if self.thread:
            self.thread.join()
    
    def _collect_events(self):
        while self.running:
            event = self._simulate_event()
            self.event_queue.put(event)
            time.sleep(0.1)
    
    def _simulate_event(self):
        return {
            'timestamp': datetime.now(),
            'event_id': 1,
            'process_name': 'explorer.exe',
            'command_line': 'C:\\Windows\\explorer.exe',
            'user': 'SYSTEM',
            'source': 'Sysmon'
        }
