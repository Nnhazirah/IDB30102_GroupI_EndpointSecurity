import pandas as pd
import numpy as np
import os
from collections import deque
from datetime import datetime

try:
    from scipy.stats import entropy as scipy_entropy
except ImportError:
    scipy_entropy = None

class RansomwareFeatureExtractor:
    """
    Extracts behavioural endpoint features for ransomware detection using sliding windows.
    Tracks file operations, Shannon entropy changes, rename spikes, directory traversal,
    and recovery interference attempts (e.g., shadow copy deletion).
    """

    FEATURE_NAMES = [
        'write_velocity',
        'entropy_current',
        'entropy_delta',
        'rename_rate',
        'directory_coverage',
        'api_call_frequency',
        'shadow_copy_attempt',
        'file_count_modified'
    ]

    def __init__(self, window_size=5):
        self.window_size = max(1, window_size)
        self.file_events = deque(maxlen=2000)
        self.api_calls = deque(maxlen=2000)
        self.entropy_history = {}

    def calculate_shannon_entropy(self, file_path_or_bytes):
        """
        Calculates Shannon entropy (0 to 8 bits).
        Accepts either a file path or raw byte sequence.
        """
        try:
            if isinstance(file_path_or_bytes, (bytes, bytearray)):
                data = file_path_or_bytes
            elif isinstance(file_path_or_bytes, str) and os.path.exists(file_path_or_bytes):
                with open(file_path_or_bytes, 'rb') as f:
                    data = f.read(65536)  # Read up to 64KB for reliable entropy calculation
            else:
                return 0.0

            if not data or len(data) == 0:
                return 0.0

            freq = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
            prob = freq[freq > 0] / len(data)

            if scipy_entropy is not None:
                return float(scipy_entropy(prob, base=2))
            else:
                return float(-np.sum(prob * np.log2(prob)))
        except Exception:
            return 0.0

    def calculate_write_velocity(self):
        """Number of file write events per second within the sliding window."""
        now = datetime.now()
        recent_writes = [
            e for e in self.file_events
            if (now - e['timestamp']).total_seconds() <= self.window_size
            and e.get('operation', '').lower() in ('write', 'modify', 'create')
        ]
        return len(recent_writes) / float(self.window_size)

    def calculate_rename_rate(self):
        """Number of file rename/extension change operations per second within the sliding window."""
        now = datetime.now()
        recent_renames = [
            e for e in self.file_events
            if (now - e['timestamp']).total_seconds() <= self.window_size
            and e.get('operation', '').lower() in ('rename', 'extension_change')
        ]
        return len(recent_renames) / float(self.window_size)

    def calculate_directory_coverage(self):
        """Number of distinct directories modified within the sliding window."""
        now = datetime.now()
        recent_dirs = set()
        for e in self.file_events:
            if (now - e['timestamp']).total_seconds() <= self.window_size:
                fp = e.get('file_path')
                if fp:
                    recent_dirs.add(os.path.dirname(str(fp)))
        return len(recent_dirs)

    def calculate_api_frequency(self):
        """Rate of suspicious or security-critical API calls per second."""
        now = datetime.now()
        recent_apis = [
            a for a in self.api_calls
            if (now - a['timestamp']).total_seconds() <= self.window_size
        ]
        return len(recent_apis) / float(self.window_size)

    def check_shadow_copy_attempt(self, event):
        """Checks for volume shadow copy deletion or recovery tampering."""
        indicators = ['vssadmin', 'shadowcopy', 'wmic', 'bcdedit', 'wbadmin', 'resize shadowstorage']
        cmd = str(event.get('command_line', '')).lower()
        api = str(event.get('api_call', '')).lower()
        proc = str(event.get('process_name', '')).lower()

        for ind in indicators:
            if ind in cmd or ind in api or ind in proc:
                return 1
        return 0

    def extract_features(self, event):
        """
        Ingests an incoming endpoint event, records it in sliding window buffers,
        and returns an extracted 8-feature dictionary for model inference.
        """
        # Ensure timestamp is a datetime object
        ts = event.get('timestamp')
        if ts is None:
            ts = datetime.now()
        elif isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except Exception:
                ts = datetime.now()
        elif isinstance(ts, pd.Timestamp):
            ts = ts.to_pydatetime()
        event['timestamp'] = ts

        # Record file event
        if 'operation' in event or 'file_path' in event:
            self.file_events.append(event)

        # Record API call
        if 'api_call' in event:
            self.api_calls.append(event)

        # Calculate entropy & delta
        current_entropy = 0.0
        entropy_delta = 0.0
        file_path = event.get('file_path')

        if file_path:
            if 'entropy' in event and isinstance(event['entropy'], (int, float)):
                current_entropy = float(event['entropy'])
            else:
                current_entropy = self.calculate_shannon_entropy(file_path)

            if file_path in self.entropy_history:
                old_entropy = self.entropy_history[file_path]
                entropy_delta = current_entropy - old_entropy
            self.entropy_history[file_path] = current_entropy
        elif 'entropy' in event and isinstance(event['entropy'], (int, float)):
            current_entropy = float(event['entropy'])
            entropy_delta = float(event.get('entropy_delta', 0.0))

        features = {
            'write_velocity': round(self.calculate_write_velocity(), 4),
            'entropy_current': round(current_entropy, 4),
            'entropy_delta': round(entropy_delta, 4),
            'rename_rate': round(self.calculate_rename_rate(), 4),
            'directory_coverage': self.calculate_directory_coverage(),
            'api_call_frequency': round(self.calculate_api_frequency(), 4),
            'shadow_copy_attempt': self.check_shadow_copy_attempt(event),
            'file_count_modified': len(self.file_events)
        }

        return features

    def reset(self):
        """Resets sliding window queues and history caches."""
        self.file_events.clear( )
        self.api_calls.clear()
        self.entropy_history.clear()
