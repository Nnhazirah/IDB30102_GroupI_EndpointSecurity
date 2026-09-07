"""
Main Agent for Ransomware Detection
Orchestrates file monitoring and feature extraction
"""

import json
import time
from file_monitor import FileSystemMonitor
from feature_extractor import FeatureExtractor


class RansomwareDetectionAgent:
    def __init__(self, config_path='agent_config.json'):
        with open(config_path, 'r') as f:
            self.config = json.load(f)
            
        self.monitor = FileSystemMonitor(self.config)
        self.extractor = FeatureExtractor(
            self.config['config']['window_seconds']
        )
        self.monitor.set_callback(self.on_operation)
        
    def on_operation(self, operation):
        self.extractor.add_operation(operation)
        features = self.extractor.get_features()
        if features:
            for f in features:
                print(f"[FEATURES] {f['process_name']}: "
                      f"Opens={f['f1_opens']}, Writes={f['f3_writes']}, "
                      f"Rate={f['f7_operation_rate']}")
                
    def start(self):
        print("[Agent] Starting ransomware detection agent...")
        self.monitor.start_monitoring()
        
    def stop(self):
        print("[Agent] Stopping agent...")
        self.monitor.stop_monitoring()
        

if __name__ == "__main__":
    agent = RansomwareDetectionAgent()
    try:
        agent.start()
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        agent.stop()
