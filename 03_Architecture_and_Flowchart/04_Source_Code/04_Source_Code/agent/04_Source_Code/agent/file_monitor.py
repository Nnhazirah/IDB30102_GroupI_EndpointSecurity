"""
File System Monitor for Ransomware Detection
Captures file operations on Windows endpoints
"""

import os
import sys
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional, Callable

# Check if running on Windows
if sys.platform == 'win32':
    try:
        import win32file
        import win32con
        WIN32_AVAILABLE = True
    except ImportError:
        WIN32_AVAILABLE = False
        print("Warning: pywin32 not installed.")
else:
    WIN32_AVAILABLE = False
    print("Warning: File monitor only works on Windows.")


class FileOperation:
    """Represents a single file operation"""
    def __init__(self, operation_type: str, process_id: int, 
                 process_name: str, file_path: str):
        self.operation_type = operation_type
        self.process_id = process_id
        self.process_name = process_name
        self.file_path = file_path
        self.timestamp = datetime.now().isoformat()
        self.file_name = os.path.basename(file_path)
        self.extension = os.path.splitext(file_path)[1].lower()
        self.depth = file_path.count(os.sep)
        
    def to_dict(self) -> Dict:
        return {
            'operation_type': self.operation_type,
            'process_id': self.process_id,
            'process_name': self.process_name,
            'file_path': self.file_path,
            'file_name': self.file_name,
            'extension': self.extension,
            'depth': self.depth,
            'timestamp': self.timestamp
        }


class FileSystemMonitor:
    """Monitors file system activities on Windows"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.operation_buffer = []
        self.running = False
        self.callback = None
        self.event_count = 0
        self.buffer_lock = threading.Lock()
        self.monitor_paths = config.get('monitoring', {}).get('included_paths', ['C:\\Users\\'])
        self.excluded_paths = config.get('monitoring', {}).get('excluded_paths', [])
        self.window_seconds = config.get('config', {}).get('window_seconds', 10)
        
    def set_callback(self, callback: Callable):
        self.callback = callback
        
    def start_monitoring(self):
        self.running = True
        print(f"[FileSystemMonitor] Starting monitoring...")
        if WIN32_AVAILABLE:
            self._monitor_loop()
        else:
            self._simulation_loop()
            
    def stop_monitoring(self):
        self.running = False
        print("[FileSystemMonitor] Stopped")
        
    def _simulation_loop(self):
        """Simulation mode for testing"""
        print("[FileSystemMonitor] SIMULATION mode")
        test_ops = [
            ('open', 'notepad.exe', 'C:\\Users\\Test\\doc.txt'),
            ('read', 'notepad.exe', 'C:\\Users\\Test\\doc.txt'),
            ('write', 'notepad.exe', 'C:\\Users\\Test\\doc.txt'),
        ]
        for op_type, proc, path in test_ops:
            if not self.running:
                break
            op = FileOperation(op_type, 1234, proc, path)
            with self.buffer_lock:
                self.operation_buffer.append(op.to_dict())
                self.event_count += 1
            if self.callback:
                self.callback(op.to_dict())
            time.sleep(0.5)
            
    def flush_buffer(self):
        with self.buffer_lock:
            if self.operation_buffer:
                print(f"[FileSystemMonitor] Flushing {len(self.operation_buffer)} ops")
                self.operation_buffer = []
                
    def get_operations(self) -> List[Dict]:
        with self.buffer_lock:
            ops = self.operation_buffer.copy()
            self.operation_buffer = []
            return ops
            
    def get_stats(self) -> Dict:
        return {
            'events_captured': self.event_count,
            'buffer_size': len(self.operation_buffer),
            'running': self.running
        }


if __name__ == "__main__":
    config = {
        'config': {'window_seconds': 10},
        'monitoring': {'included_paths': ['C:\\Users\\Public\\Test']}
    }
    monitor = FileSystemMonitor(config)
    monitor.start_monitoring()
    time.sleep(3)
    monitor.stop_monitoring()
    print("Stats:", monitor.get_stats())
