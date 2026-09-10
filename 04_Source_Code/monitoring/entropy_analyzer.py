import os
import time
import math
import threading
import numpy as np

try:
    from scipy.stats import entropy as scipy_entropy
except ImportError:
    scipy_entropy = None

class EntropyAnalyzer:
    """
    Monitors a target directory or individual files to track file entropy changes.
    Ransomware typically causes rapid entropy spikes (jumping above 7.0 - 7.5 bits)
    as plaintext documents are encrypted into pseudo-random ciphertext.
    """

    def __init__(self, watch_directory=None, scan_interval=2, entropy_threshold=7.2):
        self.watch_directory = watch_directory
        self.scan_interval = scan_interval
        self.entropy_threshold = entropy_threshold
        self.running = False
        self.entropy_cache = {}
        self.alerts = []
        self.thread = None
        self._lock = threading.Lock()

    def calculate_entropy(self, file_path_or_bytes):
        """
        Calculates Shannon entropy in bits (range: 0.0 to 8.0).
        """
        try:
            if isinstance(file_path_or_bytes, (bytes, bytearray)):
                data = file_path_or_bytes
            elif isinstance(file_path_or_bytes, str) and os.path.isfile(file_path_or_bytes):
                with open(file_path_or_bytes, 'rb') as f:
                    data = f.read(65536)  # 64 KB sample
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

    def get_entropy_delta(self, file_path):
        """
        Calculates current entropy and delta from previous recorded value.
        """
        current_entropy = self.calculate_entropy(file_path)
        with self._lock:
            if file_path in self.entropy_cache:
                old_entropy = self.entropy_cache[file_path]
                delta = current_entropy - old_entropy
            else:
                delta = 0.0
            self.entropy_cache[file_path] = current_entropy
        return current_entropy, delta

    def scan_directory(self):
        """
        Scans all files in watch_directory and checks for suspicious entropy spikes.
        """
        if not self.watch_directory or not os.path.exists(self.watch_directory):
            return []

        detected_spikes = []
        try:
            for root, _, files in os.walk(self.watch_directory):
                for fname in files:
                    full_path = os.path.join(root, fname)
                    try:
                        current_entropy, delta = self.get_entropy_delta(full_path)
                        if current_entropy >= self.entropy_threshold or delta >= 1.5:
                            alert = {
                                'file_path': full_path,
                                'entropy': round(current_entropy, 4),
                                'delta': round(delta, 4),
                                'timestamp': time.time(),
                                'suspicious': True
                            }
                            detected_spikes.append(alert)
                            with self._lock:
                                self.alerts.append(alert)
                    except (PermissionError, FileNotFoundError):
                        continue
        except Exception:
            pass

        return detected_spikes

    def start_monitoring(self):
        """Starts directory monitoring thread."""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self._monitor, daemon=True)
            self.thread.start()

    def stop_monitoring(self):
        """Stops directory monitoring thread."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def get_recent_alerts(self):
        """Returns list of flagged suspicious entropy alerts."""
        with self._lock:
            return list(self.alerts)

    def _monitor(self):
        while self.running:
            if self.watch_directory and os.path.exists(self.watch_directory):
                self.scan_directory()
            time.sleep(self.scan_interval)
