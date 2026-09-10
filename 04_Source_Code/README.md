# 04 Source Code: Endpoint Security System

This directory contains the complete source code implementation for the **IDB30102 Group I Endpoint Security** machine-learning-based behavioural ransomware detection system.

---

## 📂 Directory Structure

```text
04_Source_Code/
├── detection/
│   ├── ensemble_detector.py      # Multi-model soft/hard voting ensemble classifier
│   ├── random_forest_model.py    # Random Forest classifier with scaling & feature importance
│   ├── svm_model.py              # Support Vector Machine classifier with RBF kernel
│   └── xgboost_model.py          # XGBoost classifier with gradient boosted trees
├── monitoring/
│   ├── entropy_analyzer.py       # Shannon entropy analyzer and directory spike monitor
│   └── sysmon_collector.py       # Sysmon telemetry collector and realistic event simulator
├── preprocessing/
│   └── feature_extraction.py     # 5-second sliding window behavioural feature extractor
├── saved_models/                 # Serialized trained model weights (.pkl)
├── gui_app.py                    # Modern CustomTkinter dark-mode desktop GUI dashboard
├── run_pipeline.py               # End-to-end training, evaluation, and live simulation pipeline
└── requirements.txt              # Required Python packages with compatible version bounds
```

---

## ⚙️ Prerequisites & Installation

* **Operating System:** Windows 10 / 11 (or compatible Linux/macOS environment)
* **Python Version:** Python 3.9+ (tested and verified on Python 3.12)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🖥️ Launching the Graphical User Interface (GUI)

The system includes a modern dark-mode Security Operations Center (SOC) dashboard built with CustomTkinter.

```bash
python gui_app.py
```
*(On Windows, you can also simply double-click **`run_gui.bat`** or choose Option `[1]` in **`run.bat`**).*

### GUI Features:
* **Live Telemetry Monitor:** Displays real-time cards for Write Velocity, File Entropy, Shadow Copy Tampering, and Threat Classification.
* **Attack Simulation Controls:** Inject benign user activity, active ransomware bursts, or shadow copy deletion attacks to observe instant model classification.
* **Shannon Entropy File/Folder Scanner:** Browse any local file or folder to analyze byte randomness with color-coded risk assessment.
* **Model Benchmark & Retrain Engine:** Inspect accuracy, precision, recall, and F1 across all four models, and trigger real-time model retraining on the fly.
* **Interactive Terminal Log:** Color-coded event telemetry feed with auto-scrolling and log clearing.

---

## 🚀 Running the Command Line Pipeline (CLI)

To run headless dataset generation, model training, evaluation, and terminal simulation:

```bash
python run_pipeline.py
```

### What the CLI pipeline does:
1. **Generates / Ingests Dataset:** Creates `05_Data_or_Sample_Input/synthetic_features_dataset.csv` with 1,500 labeled samples.
2. **Trains Classifiers:** Fits each model on standardized features with 80/20 train-test split and 5-fold cross-validation.
3. **Persists Weights:** Serializes trained models and scalers to `04_Source_Code/saved_models/`.
4. **Logs Metrics:** Outputs accuracy, precision, recall, and F1-score to `06_Result_or_Expected_Outcome/model_evaluation_metrics.json`.
5. **Live Simulation:** Streams realistic Sysmon events through the 5-second sliding window feature extractor and outputs real-time threat alerts.

---

## 🔍 Module Details

### 1. `preprocessing/feature_extraction.py`
Maintains rolling queues to compute 8 key dynamic features:
* `write_velocity`: Rate of file modifications per second.
* `entropy_current`: Shannon entropy of target file (0.0 to 8.0 bits).
* `entropy_delta`: Change in entropy compared to pre-modification state.
* `rename_rate`: File rename and extension change rate.
* `directory_coverage`: Count of unique directories modified.
* `api_call_frequency`: Rate of security-relevant API invocations.
* `shadow_copy_attempt`: Detection of `vssadmin`, `bcdedit`, or `wmic` tampering.
* `file_count_modified`: Total count of files modified in the active window.

### 2. `detection/ensemble_detector.py`
Combines predictions from Random Forest, XGBoost, and SVM using probability-weighted soft voting. Aligns predictions with a 3-tier threat taxonomy (`Benign`, `Suspicious`, `Ransomware`).

### 3. `monitoring/`
* `entropy_analyzer.py`: Actively scans directories for cryptographic transformations.
* `sysmon_collector.py`: Collects or simulates realistic endpoint telemetry with benign and ransomware workloads.
