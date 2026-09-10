# Behavioural Detection of File-Encrypting Ransomware on Windows Endpoints using Machine Learning

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6?logo=windows&logoColor=white)](#)
[![Python](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](#)
[![Machine Learning](https://img.shields.io/badge/Models-RF%20%7C%20XGBoost%20%7C%20SVM%20%7C%20Ensemble-10B981)](#)
[![UI](https://img.shields.io/badge/GUI-CustomTkinter%20Dark%20Dashboard-6366F1)](#)

---

## 1. Research Overview

This research focuses on the behavioural detection of file-encrypting ransomware on Windows endpoints through machine learning. Traditional antivirus tools rely heavily on static file signatures and known hashes, making them inherently vulnerable to zero-day, packed, or polymorphic ransomware families. 

File-encrypting ransomware exhibits distinct operational characteristics during execution:
* Rapid modification and overwriting of user files (high write velocity)
* Sudden surges in data randomness (Shannon entropy transition from plaintext to ciphertext)
* Bulk file renaming and extension appending (e.g., `.locked`, `.enc`, `.wnry`)
* System recovery sabotage, including volume shadow copy deletion (`vssadmin delete shadows /all /quiet`)
* Process tampering and suspicious crypto API invocations (`CryptEncrypt`, `MoveFileExW`)

By capturing these dynamic indicators across sliding temporal windows, the proposed framework classifies endpoint activity into benign operations, suspicious anomalies, or active ransomware attacks.

---

## 2. Group Information

**Course:** IDB30102 – Security Architecture and Endpoint Defense  
**Group:** Group I – Endpoint Security  

### Research Team

| No. | Member Name | Student ID | Core Research Responsibility |
| :---: | :--- | :---: | :--- |
| 1 | **Nur Khalisah Qistina binti Muhamad** | 52215124789 | Chapter 1: Research Overview, Problem Statement & Objectives |
| 2 | **Nurfilzah Adibah binti Zakaria** | 52215124782 | Chapter 2: Literature Review, Threat Vectors & Attack Analysis |
| 3 | **Nik Nurhazirah binti Nik Hussain** | 52215226033 | Chapter 3A: Methodology, System Architecture & Sensor Design |
| 4 | **Nurin Izzah binti Juhari** | 52215124817 | Chapter 3B: Dataset Synthesis, Model Evaluation & Documentation |

---

## 3. Assigned Research Area & Scope

* **Research Domain:** Endpoint Security & Host-Based Intrusion Detection
* **Focus Area:** Early-stage behavioural detection of file-encrypting ransomware on Windows operating systems
* **Scope Boundaries:** The system focuses on feature extraction, multi-model classification, and early containment validation; it serves as a lightweight behavioural detection engine rather than a commercial Endpoint Detection and Response (EDR) suite.

---

## 4. Problem Statement

### Problem 1: Detection Limitations of Static Antivirus
Modern ransomware operators constantly mutate, pack, and obfuscate payloads to evade static hash databases. By the time a signature is distributed, the victim's data is already encrypted. While behavioural heuristics offer protection against novel strains, relying on a single indicator—such as file entropy alone—causes false positives on legitimate compressed files (ZIP, DOCX, MP4). A multi-vector approach is necessary.

### Problem 2: Limited Generalisation to Realistic Endpoint Environments
Many machine learning studies evaluate models strictly in controlled sandbox environments with synthetic conditions. In real enterprise environments, background system services, software compiling, database updates, and user document archiving generate high volumes of noisy telemetry. Machine learning models must be resilient against benign high-entropy events while maintaining sub-second detection latency.

---

## 5. Research Objectives

* **RO1 (Analysis):** Identify and characterize the runtime behavioural patterns of file-encrypting ransomware on Windows endpoints.
* **RO2 (Development):** Design and implement a multi-model machine learning architecture combining Random Forest, XGBoost, and Support Vector Machines (SVM) with sliding-window feature extraction.
* **RO3 (Evaluation):** Evaluate detection performance, cross-validation metrics, and false-positive resilience across benign workloads and simulated ransomware attacks.

---

## 6. Proposed Solution

The system introduces a 4-tier behavioural detection engine:
* **Multi-Vector Telemetry:** Tracks write velocity, Shannon entropy deltas, rename frequency, directory coverage, API rates, and recovery tampering hooks.
* **Temporal Sliding Window:** Uses a 5-second rolling window to capture burst behaviour without accumulating memory overhead.
* **Standardized Ensemble Detection:** Scales features with `StandardScaler` and applies probability-weighted soft voting across Random Forest, XGBoost, and Support Vector Machines.
* **Actionable Threat Taxonomy:** Maps threats into three operational tiers: `[BENIGN]` ($<0.40$), `[SUSPICIOUS]` ($0.40-0.79$), and `[RANSOMWARE]` ($\ge 0.80$).

---

## 7. Development Model & Research Methodology

**Development Model:** Machine Learning Development Life Cycle (MLDLC) / Iterative CRISP-DM
1. **Endpoint Domain Understanding:** Formulating ransomware attack vectors and normal user activity profiles.
2. **Data & Telemetry Ingestion:** Continuous Sysmon log monitoring and file-system event buffering.
3. **Feature Engineering & Preprocessing:** 5-second temporal sliding windows, Shannon entropy calculation, delta tracking, and robust feature standardization.
4. **Ensemble Model Training & Validation:** Training Random Forest, XGBoost, and SVM with 5-fold cross-validation and soft probability voting.
5. **Real-Time Evaluation & Mitigation:** Threshold-based risk classification and automated alerting on desktop dashboard.

---

## 8. System Architecture

```text
+-----------------------------------------------------------------------------------+
|                           LAYER 1: DATA COLLECTION                                |
|  - Windows Sysmon telemetry (Process creation, File operations, Registry)         |
|  - Active Shannon entropy monitoring (0.0 to 8.0 bits scale)                      |
|  - System recovery watchdog (vssadmin, bcdedit, wbadmin monitoring)               |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                          LAYER 2: FEATURE EXTRACTION                              |
|  - 5-second sliding temporal aggregation window                                   |
|  - Extracted features:                                                            |
|    1. write_velocity (writes/s)           5. directory_coverage (count)           |
|    2. entropy_current (bits)              6. api_call_frequency (calls/s)         |
|    3. entropy_delta (Δ bits)              7. shadow_copy_attempt (0 or 1)         |
|    4. rename_rate (renames/s)             8. file_count_modified (count)          |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                    LAYER 3: MACHINE LEARNING DETECTION ENGINE                     |
|  - Feature standardization via StandardScaler                                     |
|  - Multi-Model ensemble:                                                          |
|    • Random Forest (100 estimators, balanced class weights)                       |
|    • Extreme Gradient Boosting / XGBoost (depth 6, learning rate 0.1)             |
|    • Support Vector Machine / SVM (RBF kernel, probability estimation)            |
|  - Calibrated probability soft-voting mechanism                                   |
+-----------------------------------------------------------------------------------+
                                         │
                                         ▼
+-----------------------------------------------------------------------------------+
|                           LAYER 4: OUTPUT & RESPONSE                              |
|  - 3-Tier Threat Taxonomy:                                                        |
|    • P(Ransomware) < 0.40  ==> [BENIGN]     (Permit operation)                    |
|    • 0.40 ≤ P < 0.80       ==> [SUSPICIOUS] (Log for audit, notify administrator) |
|    • P(Ransomware) ≥ 0.80  ==> [RANSOMWARE] (Trigger alert, process containment)  |
|  - Real-time logging feed and modern CustomTkinter SOC GUI dashboard              |
+-----------------------------------------------------------------------------------+
```

---

## 9. Repository Structure

```text
IDB30102_GroupI_EndpointSecurity/
├── 01_Research_Papers/             # Academic papers, literature review sources & gap analysis
├── 02_Literature_Review/           # Comprehensive literature synthesis and comparison matrix
├── 03_Architecture_and_Flowchart/  # Architectural design diagrams and flowchart specifications
├── 04_Source_Code/                 # Complete source code implementation
│   ├── detection/                  # Machine learning detectors (RF, SVM, XGBoost, Ensemble)
│   ├── monitoring/                 # Sysmon telemetry collector & Shannon entropy monitor
│   ├── preprocessing/              # 5-second sliding window feature extractor
│   ├── saved_models/               # Serialized trained model weights (.pkl)
│   ├── gui_app.py                  # Modern CustomTkinter dark-mode desktop GUI dashboard
│   ├── run_pipeline.py             # CLI training, evaluation, and simulation pipeline
│   ├── run.bat                     # Launcher inside source directory
│   └── requirements.txt            # Python dependencies with compatible version bounds
├── 05_Data_or_Sample_Input/        # 1,500 labeled feature instances & sample Sysmon logs
├── 06_Result_or_Expected_Outcome/  # Model evaluation metrics, confusion matrix & benchmark data
├── 07_References/                  # Full bibliography in IEEE and APA formats
├── run.bat                         # Interactive Windows launcher menu (GUI or CLI)
├── run_gui.bat                     # Direct one-click GUI launcher
└── README.md                       # Project documentation
```

---

## 10. Quick Start & Execution Guide

### Option A: Launch via Batch File (Recommended on Windows)

Double-click **`run.bat`** in the root directory to open the interactive menu:

```text
===========================================================================
  IDB30102 GROUP I: ENDPOINT SECURITY
  Behavioural Detection of File-Encrypting Ransomware using Machine Learning
===========================================================================

  Please select an operating mode:
  [1] Launch Modern Desktop GUI Dashboard (Recommended)
  [2] Run Terminal Evaluation and Training Pipeline (CLI)
  [3] Install / Verify Dependencies (requirements.txt)
  [4] Exit
```

Or simply double-click **`run_gui.bat`** to start the desktop dashboard directly.

---

### Option B: Manual Command Line Execution

1. **Install Prerequisites:**
   ```bash
   pip install -r 04_Source_Code/requirements.txt
   ```

2. **Launch the Desktop GUI:**
   ```bash
   python 04_Source_Code/gui_app.py
   ```

3. **Run the Terminal Evaluation Pipeline:**
   ```bash
   python 04_Source_Code/run_pipeline.py
   ```

---

## 11. Experimental Results & Literature Baselines

All models were evaluated on 1,500 labeled instances (900 benign endpoint records and 600 simulated ransomware bursts) using stratified 80/20 train-test splits and 5-fold cross-validation:

| Classifier Model | Accuracy | Precision | Recall | F1-Score | Literature Baseline |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **Random Forest** | 100.0% | 100.0% | 100.0% | 1.0000 | 98.1% (Elsersy et al., 2024) |
| **Support Vector Machine (SVM)** | 100.0% | 100.0% | 100.0% | 1.0000 | 97.3% (Zirari et al., 2025) |
| **XGBoost Classifier** | 100.0% | 100.0% | 100.0% | 1.0000 | 98.5% (Muppidi & Sureshkumar, 2025) |
| **Multi-Model Soft Ensemble** | **100.0%** | **100.0%** | **100.0%** | **1.0000** | **98.9% (Surya & Sivakumar, 2024)** |

---

## 12. License & Academic Integrity

This project is submitted as an academic group assignment for course **IDB30102**. All research papers, methodologies, and tools cited are referenced under standard academic guidelines in [`07_References/`](07_References/).
