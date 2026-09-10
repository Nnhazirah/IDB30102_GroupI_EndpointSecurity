import threading
import time
import queue
import random
import os
import json
from datetime import datetime

class SysmonCollector:
    """
    Collects or simulates Windows Sysmon & Endpoint Security telemetry.
    Supports real-time stream ingestion, synthetic replay of benign and ransomware
    workloads, and log queue buffering for feature extraction.
    """

    # Sysmon Event IDs of interest
    EVENT_ID_PROCESS_CREATE = 1
    EVENT_ID_FILE_CREATE_TIME = 2
    EVENT_ID_NETWORK_CONNECT = 3
    EVENT_ID_PROCESS_TERMINATED = 5
    EVENT_ID_DRIVER_LOAD = 6
    EVENT_ID_IMAGE_LOAD = 7
    EVENT_ID_CREATE_REMOTE_THREAD = 8
    EVENT_ID_RAW_ACCESS_READ = 9
    EVENT_ID_PROCESS_ACCESS = 10
    EVENT_ID_FILE_CREATE = 11
    EVENT_ID_REGISTRY_EVENT = 12
    EVENT_ID_FILE_STREAM_HASH = 15
    EVENT_ID_PIPE_EVENT = 17
    EVENT_ID_DNS_QUERY = 22
    EVENT_ID_FILE_DELETE = 23
    EVENT_ID_FILE_DELETE_DETECTED = 26

    def __init__(self, event_queue=None, mode='simulation'):
        self.event_queue = event_queue if event_queue is not None else queue.Queue()
        self.mode = mode  # 'simulation', 'file_replay', or 'live'
        self.running = False
        self.thread = None
        self.simulation_scenario = 'mixed'  # 'benign', 'ransomware', or 'mixed'

    def start_collection(self, scenario='mixed'):
        """Starts background event ingestion thread."""
        self.simulation_scenario = scenario
        self.running = True
        self.thread = threading.Thread(target=self._run_collector, daemon=True)
        self.thread.start()

    def stop_collection(self):
        """Stops event collection."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)

    def replay_from_file(self, filepath):
        """Loads events from a JSON or CSV file and pushes them to event_queue."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Event file not found: {filepath}")

        if filepath.endswith('.json'):
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                for item in data:
                    self.event_queue.put(item)
        elif filepath.endswith('.csv'):
            import pandas as pd
            df = pd.read_csv(filepath)
            for _, row in df.iterrows():
                self.event_queue.put(row.to_dict())

    def _run_collector(self):
        while self.running:
            if self.mode == 'simulation':
                event = self._generate_simulated_event()
                self.event_queue.put(event)
                time.sleep(random.uniform(0.05, 0.2))
            else:
                # Live polling fallback if Sysmon is queried
                time.sleep(1)

    def _generate_simulated_event(self):
        """Generates a realistic event based on active simulation scenario."""
        if self.simulation_scenario == 'benign':
            return self._simulate_benign_event()
        elif self.simulation_scenario == 'ransomware':
            return self._simulate_ransomware_event()
        else:
            # Mixed scenario: 70% benign, 30% ransomware bursts
            if random.random() < 0.7:
                return self._simulate_benign_event()
            else:
                return self._simulate_ransomware_event()

    def _simulate_benign_event(self):
        benign_processes = [
            ('explorer.exe', 'C:\\Windows\\explorer.exe', 'read'),
            ('chrome.exe', 'C:\\Program Files\\Google\\Chrome\\chrome.exe', 'read'),
            ('notepad.exe', 'C:\\Windows\\notepad.exe', 'write'),
            ('svchost.exe', 'C:\\Windows\\System32\\svchost.exe -k netsvcs', 'read'),
            ('code.exe', 'C:\\Users\\User\\AppData\\Local\\Programs\\VSCode\\code.exe', 'write'),
            ('word.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', 'write')
        ]
        benign_files = [
            'C:\\Users\\User\\Documents\\report.docx',
            'C:\\Users\\User\\Documents\\notes.txt',
            'C:\\Users\\User\\AppData\\Local\\Temp\\cache.dat',
            'C:\\Users\\User\\Downloads\\invoice.pdf',
            'C:\\Users\\User\\Projects\\script.py'
        ]
        proc, cmd, default_op = random.choice(benign_processes)
        file_path = random.choice(benign_files)

        return {
            'timestamp': datetime.now(),
            'event_id': self.EVENT_ID_FILE_CREATE if default_op == 'write' else self.EVENT_ID_PROCESS_CREATE,
            'process_name': proc,
            'command_line': cmd,
            'user': 'NT AUTHORITY\\SYSTEM' if 'svchost' in proc else 'ENDPOINT-PC\\User',
            'source': 'Sysmon',
            'operation': default_op,
            'file_path': file_path,
            'entropy': round(random.uniform(2.8, 5.2), 3),
            'api_call': 'NtWriteFile' if default_op == 'write' else 'NtOpenFile'
        }

    def _simulate_ransomware_event(self):
        ransom_families = ['wannacry.exe', 'lockbit.exe', 'revil.exe', 'blackcat.exe', 'encryptor.exe']
        ransom_extensions = ['.locked', '.enc', '.crypted', '.lockbit', '.wnry']
        suspicious_apis = [
            ('vssadmin.exe delete shadows /all /quiet', 'vssadmin delete shadows'),
            ('bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures', 'bcdedit tamper'),
            ('wbadmin.exe delete catalog -quiet', 'wbadmin delete'),
            ('CryptEncrypt', 'CryptEncrypt'),
            ('MoveFileExW', 'MoveFileExW')
        ]

        # 25% chance of recovery tampering / shadow copy deletion
        if random.random() < 0.25:
            cmd, api = random.choice(suspicious_apis[:3])
            return {
                'timestamp': datetime.now(),
                'event_id': self.EVENT_ID_PROCESS_CREATE,
                'process_name': 'cmd.exe',
                'command_line': cmd,
                'user': 'ENDPOINT-PC\\User',
                'source': 'Sysmon',
                'operation': 'process_create',
                'file_path': None,
                'entropy': 0.0,
                'api_call': api
            }

        proc = random.choice(ransom_families)
        ext = random.choice(ransom_extensions)
        target_file = f"C:\\Users\\User\\Documents\\Financial_Record_{random.randint(1, 1000)}{ext}"

        return {
            'timestamp': datetime.now(),
            'event_id': self.EVENT_ID_FILE_CREATE,
            'process_name': proc,
            'command_line': f"C:\\Temp\\{proc}",
            'user': 'ENDPOINT-PC\\User',
            'source': 'Sysmon',
            'operation': random.choice(['write', 'rename']),
            'file_path': target_file,
            'entropy': round(random.uniform(7.4, 7.99), 3),  # High entropy ciphertext
            'api_call': 'CryptEncrypt'
        }
