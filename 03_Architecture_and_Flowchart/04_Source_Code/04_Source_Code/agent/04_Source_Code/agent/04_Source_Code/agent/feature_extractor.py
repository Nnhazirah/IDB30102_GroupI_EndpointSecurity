"""
Feature Extractor for Ransomware Detection
Extracts 8 behavioral features from file operations
"""

import json
import time
import threading
from datetime import datetime
from typing import Dict, List
from collections import defaultdict, deque


class SlidingWindowCounter:
    """Counts events within a sliding time window"""
    def __init__(self, window_seconds: int = 60):
        self.window = window_seconds
        self._events = deque()
        self._lock = threading.Lock()
        
    def add_event(self):
        now = time.monotonic()
        with self._lock:
            self._events.append(now)
            self._prune(now)
            
    def get_count(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            return len(self._events)
            
    def _prune(self, now: float):
        cutoff = now - self.window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


class FeatureExtractor:
    """Extracts 8 behavioral features for ransomware detection"""
    
    def __init__(self, window_seconds: int = 10):
        self.window_seconds = window_seconds
        self.operations_by_process = defaultdict(list)
        self._lock = threading.Lock()
        
        # Feature counters
        self.open_counter = SlidingWindowCounter(window_seconds)
        self.read_counter = SlidingWindowCounter(window_seconds)
        self.write_counter = SlidingWindowCounter(window_seconds)
        self.delete_counter = SlidingWindowCounter(window_seconds)
        
    def add_operation(self, operation: Dict):
        with self._lock:
            key = f"{operation['process_id']}_{operation['process_name']}"
            self.operations_by_process[key].append(operation)
            
            op_type = operation.get('operation_type', '')
            if op_type == 'open':
                self.open_counter.add_event()
            elif op_type == 'read':
                self.read_counter.add_event()
            elif op_type == 'write':
                self.write_counter.add_event()
            elif op_type == 'delete':
                self.delete_counter.add_event()
                
    def get_features(self) -> List[Dict]:
        features = []
        current_time = datetime.now()
        
        with self._lock:
            for key, operations in self.operations_by_process.items():
                # Filter operations within window
                window_ops = []
                for op in operations:
                    try:
                        op_time = datetime.fromisoformat(op['timestamp'])
                        if (current_time - op_time).seconds <= self.window_seconds:
                            window_ops.append(op)
                    except:
                        continue
                        
                if not window_ops:
                    continue
                    
                # Extract features
                pid, pname = key.split('_', 1)
                
                # Count operation types
                opens = sum(1 for op in window_ops if op['operation_type'] == 'open')
                reads = sum(1 for op in window_ops if op['operation_type'] == 'read')
                writes = sum(1 for op in window_ops if op['operation_type'] == 'write')
                deletes = sum(1 for op in window_ops if op['operation_type'] == 'delete')
                
                # Unique extensions
                extensions = set()
                depths = []
                for op in window_ops:
                    if 'extension' in op and op['extension']:
                        extensions.add(op['extension'].lower())
                    if 'depth' in op:
                        depths.append(op['depth'])
                        
                unique_ext = len(extensions)
                max_depth = max(depths) if depths else 0
                
                # Operation rate
                if len(window_ops) > 1:
                    try:
                        first = datetime.fromisoformat(window_ops[0]['timestamp'])
                        last = datetime.fromisoformat(window_ops[-1]['timestamp'])
                        duration = max(1, (last - first).seconds)
                        rate = len(window_ops) / duration
                    except:
                        rate = 0
                else:
                    rate = 0
                    
                # Entropy (simplified)
                entropy = 0.5 if writes > 0 else 0.0
                
                features.append({
                    'process_id': int(pid),
                    'process_name': pname,
                    'window_seconds': self.window_seconds,
                    'timestamp': datetime.now().isoformat(),
                    'f1_opens': opens,
                    'f2_reads': reads,
                    'f3_writes': writes,
                    'f4_deletes': deletes,
                    'f5_unique_extensions': unique_ext,
                    'f6_max_depth': max_depth,
                    'f7_operation_rate': round(rate, 2),
                    'f8_entropy_change': entropy,
                    'total_operations': len(window_ops)
                })
                
            # Cleanup old operations
            for key in list(self.operations_by_process.keys()):
                self.operations_by_process[key] = [
                    op for op in self.operations_by_process[key]
                    if (current_time - datetime.fromisoformat(op['timestamp'])).seconds <= self.window_seconds
                ]
                
        return features
        
    def reset(self):
        with self._lock:
            self.operations_by_process = defaultdict(list)
            
    def get_stats(self) -> Dict:
        with self._lock:
            total = sum(len(ops) for ops in self.operations_by_process.values())
            return {
                'total_operations': total,
                'processes_tracked': len(self.operations_by_process)
            }


if __name__ == "__main__":
    extractor = FeatureExtractor(10)
    
    # Test with sample operations
    sample_ops = [
        {'process_id': 1234, 'process_name': 'notepad.exe', 
         'operation_type': 'open', 'extension': '.txt', 'depth': 4,
         'timestamp': datetime.now().isoformat()},
        {'process_id': 1234, 'process_name': 'notepad.exe',
         'operation_type': 'write', 'extension': '.txt', 'depth': 4,
         'timestamp': datetime.now().isoformat()},
    ]
    
    for op in sample_ops:
        extractor.add_operation(op)
        
    features = extractor.get_features()
    print("Extracted Features:", json.dumps(features, indent=2))
    print("Stats:", extractor.get_stats())
