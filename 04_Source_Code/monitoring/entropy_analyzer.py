import os
import numpy as np
from scipy.stats import entropy
import threading
import time

class EntropyAnalyzer:
    
    def __init__(self, watch_directory):
        self.watch_directory = watch_directory
        self.running = False
        self.entropy_cache = {}
        self.thread = None
        
    def start_monitoring(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor)
        self.thread.start()
        
    def stop_monitoring(self):
        self.running = False
        if self.thread:
            self.thread.join()
    
    def calculate_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read(4096)
                if not data:
                    return 0
                freq = np.bincount(np.frombuffer(data, dtype=np.uint8))
                prob = freq[freq > 0] / len(data)
                return entropy(prob, base=2)
        except:
            return 0
    
    def get_entropy_delta(self, file_path):
        current_entropy = self.calculate_entropy(file_path)
        if file_path in self.entropy_cache:
            old_entropy = self.entropy_cache[file_path]
            delta = current_entropy - old_entropy
        else:
            delta = 0
        self.entropy_cache[file_path] = current_entropy
        return current_entropy, delta
    
    def _monitor(self):
        while self.running:
            time.sleep(1)
