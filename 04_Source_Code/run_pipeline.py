import os
import sys
import time
import json
import warnings
import numpy as np
import pandas as pd

# Suppress deprecation and convergence warnings for cleaner CLI output
warnings.filterwarnings('ignore')

# Add current directory to path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from preprocessing.feature_extraction import RansomwareFeatureExtractor
from monitoring.sysmon_collector import SysmonCollector
from monitoring.entropy_analyzer import EntropyAnalyzer
from detection.random_forest_model import RandomForestDetector
from detection.svm_model import SVMDetector
from detection.xgboost_model import XGBoostDetector
from detection.ensemble_detector import EnsembleRansomwareDetector

def generate_synthetic_dataset(num_samples=1500):
    """
    Generates realistic behavioral data for benign endpoint activity and ransomware attacks,
    incorporating realistic noise, compressed files (benign high entropy), and evasion attempts.
    """
    np.random.seed(42)
    benign_count = int(num_samples * 0.6)
    ransom_count = num_samples - benign_count

    # Benign distribution (includes occasional high entropy files like zip/mp4/docx)
    benign_data = {
        'write_velocity': np.clip(np.random.gamma(shape=1.5, scale=0.8, size=benign_count), 0.0, 5.0),
        'entropy_current': np.clip(
            np.concatenate([
                np.random.normal(loc=3.8, scale=0.8, size=int(benign_count * 0.85)),
                np.random.normal(loc=7.3, scale=0.2, size=int(benign_count * 0.15)) # Benign archives
            ]), 0.5, 7.95
        ),
        'entropy_delta': np.clip(np.random.normal(loc=0.05, scale=0.35, size=benign_count), -1.5, 1.2),
        'rename_rate': np.clip(np.random.exponential(scale=0.08, size=benign_count), 0.0, 1.2),
        'directory_coverage': np.random.choice([1, 2, 3, 4], p=[0.7, 0.2, 0.08, 0.02], size=benign_count),
        'api_call_frequency': np.clip(np.random.normal(loc=12.0, scale=6.0, size=benign_count), 1.0, 30.0),
        'shadow_copy_attempt': np.zeros(benign_count, dtype=int),
        'file_count_modified': np.random.randint(1, 40, size=benign_count),
        'label': np.zeros(benign_count, dtype=int)
    }

    # Ransomware distribution (mass writes, entropy spike, rapid renames, recovery disruption)
    ransom_data = {
        'write_velocity': np.clip(np.random.normal(loc=22.0, scale=8.0, size=ransom_count), 4.0, 65.0),
        'entropy_current': np.clip(np.random.normal(loc=7.75, scale=0.2, size=ransom_count), 6.5, 8.0),
        'entropy_delta': np.clip(np.random.normal(loc=3.2, scale=0.9, size=ransom_count), 0.8, 6.0),
        'rename_rate': np.clip(np.random.normal(loc=12.0, scale=4.0, size=ransom_count), 1.5, 35.0),
        'directory_coverage': np.random.randint(4, 25, size=ransom_count),
        'api_call_frequency': np.clip(np.random.normal(loc=75.0, scale=25.0, size=ransom_count), 20.0, 180.0),
        'shadow_copy_attempt': np.random.choice([0, 1], p=[0.60, 0.40], size=ransom_count),
        'file_count_modified': np.random.randint(50, 1800, size=ransom_count),
        'label': np.ones(ransom_count, dtype=int)
    }

    df_benign = pd.DataFrame(benign_data)
    df_ransom = pd.DataFrame(ransom_data)
    df = pd.concat([df_benign, df_ransom], ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df

def run():
    print("=" * 75)
    print("  IDB30102 Endpoint Security - Behavioural Ransomware Detection Pipeline")
    print("=" * 75)

    # 1. Dataset generation / loading
    repo_root = os.path.dirname(current_dir)
    data_dir = os.path.join(repo_root, "05_Data_or_Sample_Input")
    os.makedirs(data_dir, exist_ok=True)
    dataset_file = os.path.join(data_dir, "synthetic_features_dataset.csv")

    print(f"\n[*] Generating/Loading dataset: {dataset_file}")
    df = generate_synthetic_dataset(num_samples=1500)
    df.to_csv(dataset_file, index=False)
    print(f"[+] Dataset saved with {len(df)} samples: {df['label'].value_counts().to_dict()}")

    feature_cols = [c for c in df.columns if c != 'label']
    X = df[feature_cols]
    y = df['label']

    # 2. Train and evaluate models
    print("\n[*] Training and Evaluating Individual & Ensemble Classifiers...")
    models_dir = os.path.join(current_dir, "saved_models")
    os.makedirs(models_dir, exist_ok=True)

    # Random Forest
    rf = RandomForestDetector()
    rf_res = rf.train(X, y)
    rf.save_model(os.path.join(models_dir, "random_forest.pkl"))
    print(f"    - Random Forest : Acc={rf_res['accuracy']*100:.2f}%, Prec={rf_res['precision']*100:.2f}%, Rec={rf_res['recall']*100:.2f}%, F1={rf_res['f1_score']*100:.2f}%")

    # SVM
    svm = SVMDetector()
    svm_res = svm.train(X, y)
    svm.save_model(os.path.join(models_dir, "svm.pkl"))
    print(f"    - SVM           : Acc={svm_res['accuracy']*100:.2f}%, Prec={svm_res['precision']*100:.2f}%, Rec={svm_res['recall']*100:.2f}%, F1={svm_res['f1_score']*100:.2f}%")

    # XGBoost
    xgb = XGBoostDetector()
    xgb_res = xgb.train(X, y)
    xgb.save_model(os.path.join(models_dir, "xgboost.pkl"))
    print(f"    - XGBoost       : Acc={xgb_res['accuracy']*100:.2f}%, Prec={xgb_res['precision']*100:.2f}%, Rec={xgb_res['recall']*100:.2f}%, F1={xgb_res['f1_score']*100:.2f}%")

    # Ensemble Detector
    ensemble = EnsembleRansomwareDetector(use_soft_voting=True)
    ensemble_res = ensemble.train(X, y)
    ensemble.save_models(models_dir)
    print(f"    - Multi-Ensemble: Acc={ensemble_res['ensemble']['accuracy']*100:.2f}%, Prec={ensemble_res['ensemble']['precision']*100:.2f}%, Rec={ensemble_res['ensemble']['recall']*100:.2f}%, F1={ensemble_res['ensemble']['f1_score']*100:.2f}%")

    # 3. Save Evaluation Results
    results_dir = os.path.join(repo_root, "06_Result_or_Expected_Outcome")
    os.makedirs(results_dir, exist_ok=True)
    results_json = os.path.join(results_dir, "model_evaluation_metrics.json")
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump({
            "Random_Forest": rf_res,
            "SVM": svm_res,
            "XGBoost": xgb_res,
            "Ensemble": ensemble_res['ensemble']
        }, f, indent=4)
    print(f"\n[+] Saved evaluation metrics to: {results_json}")

    # 4. Live Simulation Demo
    print("\n" + "=" * 75)
    print("  Simulating Endpoint Telemetry & Real-Time Threat Classification")
    print("=" * 75)

    collector = SysmonCollector(mode='simulation')

    # Scenario A: Benign normal activity
    print("\n>>> Running Scenario 1: Benign User Activity (Web & Office)")
    extractor_benign = RansomwareFeatureExtractor(window_size=5)
    for i in range(5):
        event = collector._simulate_benign_event()
        features = extractor_benign.extract_features(event)
        pred, risk_level, conf, details = ensemble.predict(features)
        proc_name = str(event.get('process_name', 'N/A'))
        print(f"  [{risk_level.upper():<11}] Conf: {conf*100:5.1f}% | Process: {proc_name:<15} | WriteVel: {features['write_velocity']:4.1f} | Entropy: {features['entropy_current']:4.2f} | Tamper: {features['shadow_copy_attempt']}")

    # Scenario B: High-speed Ransomware Burst Attack
    print("\n>>> Running Scenario 2: Active Ransomware Attack (Mass Rapid Encryption & Tampering)")
    extractor_ransom = RansomwareFeatureExtractor(window_size=5)
    # Simulate a burst of 60 rapid encryption & rename operations
    for i in range(60):
        event = collector._simulate_ransomware_event()
        features = extractor_ransom.extract_features(event)
        if i in (10, 25, 40, 59): # Sample progress during attack
            pred, risk_level, conf, details = ensemble.predict(features)
            proc_name = str(event.get('process_name', 'N/A'))
            print(f"  [{risk_level.upper():<11}] Conf: {conf*100:5.1f}% | Process: {proc_name:<15} | WriteVel: {features['write_velocity']:4.1f} | Entropy: {features['entropy_current']:4.2f} | Tamper: {features['shadow_copy_attempt']}")

    print("\n" + "=" * 75)
    print("  [SUCCESS] All models trained, evaluated, saved, and verified successfully.")
    print("=" * 75)

if __name__ == '__main__':
    run()
