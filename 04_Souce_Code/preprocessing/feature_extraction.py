import pandas as pd
import numpy as np
from scipy.stats import entropy
from collections import deque
import psutil
import os

class RansomwareFeatureExtractor:
    
    def __init__(self, window_size=5):
        self.window_size = window_size
        self.file_events = deque(maxlen=1000)
        self.api_calls = deque(maxlen=1000)
        self.entropy_history = {}
        
    def calculate_shannon_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)
                if not data:
                    return 0
                freq = np.bincount(np.frombuffer(data, dtype=np.uint8))
                prob = freq[freq > 0] / len(data)
                return entropy(prob, base=2)
        except:
            return 0
    
    def calculate_write_velocity(self):
        now = pd.Timestamp.now()
        recent_events = [e for e in self.file_events 
                        if (now - e['timestamp']).seconds < self.window_size]
        writes = [e for e in recent_events if e['operation'] == 'write']
        return len(writes) / self.window_size
    
    def extract_features(self, event):
        features = {
            'write_velocity': self.calculate_write_velocity(),
            'entropy_current': 0,
            'entropy_delta': 0,
            'rename_rate': 0,
            'directory_coverage': 0,
            'api_call_frequency': 0,
            'shadow_copy_attempt': 0,
            'file_count_modified': 0
        }
        
        if 'file_path' in event:
            features['entropy_current'] = self.calculate_shannon_entropy(
                event['file_path']
            )
            if event['file_path'] in self.entropy_history:
                old_entropy = self.entropy_history[event['file_path']]
                features['entropy_delta'] = features['entropy_current'] - old_entropy
            self.entropy_history[event['file_path']] = features['entropy_current']
        
        now = pd.Timestamp.now()
        recent_events = [e for e in self.file_events 
                        if (now - e['timestamp']).seconds < self.window_size]
        renames = [e for e in recent_events if e['operation'] == 'rename']
        features['rename_rate'] = len(renames) / self.window_size
        
        if 'api_call' in event and 'vssadmin' in str(event['api_call']):
            features['shadow_copy_attempt'] = 1
        
        features['file_count_modified'] = len(self.file_events)
        
        return features
