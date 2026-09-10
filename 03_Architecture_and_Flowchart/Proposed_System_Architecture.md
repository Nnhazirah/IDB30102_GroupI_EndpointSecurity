# Proposed System Architecture

This document provides the formal architectural specification for the **Machine-Learning-Based Behavioural Detection System for File-Encrypting Ransomware on Windows Endpoints** (IDB30102 Group I).

---

## 1. Architectural Overview

The proposed system adopts a modular four-tier pipelined architecture designed for low latency, high detection precision, and resilience against polymorphic ransomware families.

```text
+-------------------------------------------------------------------------------+
|                        LAYER 1: DATA COLLECTION                               |
|  - Windows Sysmon Telemetry (Process, File, Registry, Network events)         |
|  - Real-Time File System Observer (File I/O, Creates, Writes, Renames)        |
|  - Continuous Shannon Entropy Monitor (0.0 - 8.0 bits calculation)            |
|  - Recovery Tampering Watchdog (vssadmin, bcdedit, wbadmin monitoring)         |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
|                       LAYER 2: FEATURE EXTRACTION                             |
|  - 5-Second Sliding Window Temporal Aggregator                                |
|  - Features Extracted:                                                        |
|      1. write_velocity (writes/sec)      5. directory_coverage (count)        |
|      2. entropy_current (bits)           6. api_call_frequency (calls/sec)    |
|      3. entropy_delta (Δ bits)           7. shadow_copy_attempt (0/1)          |
|      4. rename_rate (renames/sec)        8. file_count_modified (count)       |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
|                   LAYER 3: MACHINE LEARNING DETECTION ENGINE                  |
|  - Feature Standardization & Normalization (StandardScaler)                   |
|  - Parallel Model Inference:                                                  |
|      ├── Random Forest Classifier (100 trees, depth 10, balanced weights)     |
|      ├── Extreme Gradient Boosting (XGBoost) (learning rate 0.1, depth 6)     |
|      └── Support Vector Machine (SVM) (RBF kernel, probability calibration)   |
|  - Multi-Model Soft Voting Ensemble (Averaged Probability Vector)              |
+-------------------------------------------------------------------------------+
                                      │
                                      ▼
+-------------------------------------------------------------------------------+
|                        LAYER 4: OUTPUT & RESPONSE                             |
|  - Risk Classification & Decision Engine:                                     |
|      ├── P(Ransomware) < 0.40  ==> [BENIGN] (Log & permit operation)          |
|      ├── 0.40 ≤ P < 0.80       ==> [SUSPICIOUS] (Elevate audit & notify SOC)  |
|      └── P(Ransomware) ≥ 0.80  ==> [RANSOMWARE] (Trigger defensive response)  |
|  - Automated Response Actions:                                                |
|      ├── Generate High-Priority Alert with Confidence & Feature Breakdown     |
|      ├── Suspend / Terminate Malicious Process Tree                           |
|      └── Preserve Endpoint System State & Isolate Network Interface           |
+-------------------------------------------------------------------------------+
```

---

## 2. Layer Specifications

### Layer 1: Data Collection
* **Sysmon Telemetry:** Collects system-wide process creations (Event ID 1), file creation and modification timestamps (Event ID 2, 11), and process termination events.
* **File I/O Observer:** Tracks rapid file system operations across user directories (`Desktop`, `Documents`, `Downloads`).
* **Entropy Monitor:** Samples up to 64KB per modified file to calculate byte frequency distribution and Shannon entropy.
* **Tampering Watchdog:** Inspects command-line arguments of spawned processes to detect shadow copy deletion or recovery service disabling.

### Layer 2: Feature Extraction & Preprocessing
* **Temporal Aggregation:** Implements a sliding window $W = 5.0\text{ seconds}$ to capture bursts of activity while avoiding memory accumulation.
* **Feature Vector:**
  $$\mathbf{x} = [v_{\text{write}}, H_{\text{curr}}, \Delta H, v_{\text{rename}}, N_{\text{dir}}, f_{\text{api}}, I_{\text{shadow}}, N_{\text{files}}]$$
* **Standardization:** Transforms raw non-stationary values into zero-mean, unit-variance distributions:
  $$z = \frac{x - \mu}{\sigma}$$

### Layer 3: Machine Learning Detection Engine
* **Model Diversity:** Integrates diverse algorithmic paradigms (bagged decision trees, boosted decision trees, and maximum-margin kernel methods) to reduce individual inductive biases.
* **Soft Voting Formula:**
  $$P(\text{Ransomware} \mid \mathbf{x}) = \frac{1}{3} \sum_{m \in \{\text{RF}, \text{XGB}, \text{SVM}\}} P_m(y = 1 \mid \mathbf{x})$$

### Layer 4: Output & Response
* Applies risk thresholds to prevent false positive disruptions while ensuring rapid response against destructive outbreaks.
* Generates persistent JSON and dashboard telemetry logs for forensic audit.
