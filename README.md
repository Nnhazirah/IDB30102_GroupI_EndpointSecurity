# Behavioural Detection of File-Encrypting Ransomware on Windows Endpoints using Machine Learning

## 1. Research Overview

This research focuses on the behavioural detection of file-encrypting ransomware on Windows endpoints using machine learning. File-encrypting ransomware can perform malicious activities such as rapid file modification, file encryption, file renaming, extension changes, changes in file entropy, suspicious process activity and attempts to interfere with recovery mechanisms.

The research investigates how behavioural characteristics such as file-system activity, file writing and renaming, entropy changes and process/API behaviour can be used as features for machine-learning-based ransomware detection.

---

## 2. Group Information

**Group:** Group I – Endpoint Security

### Group Members

| No. | Name | Student ID | Main Responsibility |
|-----|------|------------|---------------------|
| 1 | [NUR KHALISAH QISTINA BINTI MUHAMAD] | [52215124789] | Chapter 1, README.md |
| 2 | [NURFILZAH ADIBAH BINTI ZAKARIA] | [52215124782] | Chapter 2, Literature Review |
| 3 | [NIK NURHAZIRAH BINTI NIK HUSSAIN] | [52215226033] | Chapter 3A, Methodology and Architecture |
| 4 | [NURIN IZZAH BINTI JUHARI] | [52215124817] | Chapter 3B, Data, Evaluation and References |

---

## 3. Assigned Research Area

**Research Area:** Endpoint Security

**Research Topic:** Behavioural Detection of File-Encrypting Ransomware on Windows Endpoints using Machine Learning

The research focuses on detecting ransomware-related behaviour on Windows endpoints by analysing multiple behavioural characteristics and applying machine learning for classification.

---

## 4. Research Problem

The research addresses two main problems.

### Problem 1: Detection Limitations

Ransomware that encrypts files can show different behaviours, including rapid file alteration, file renaming, entropy changes and suspicious process activity. However, relying on a single behavioural indicator may not accurately distinguish ransomware from legitimate activity. For example, legitimate compressed or encrypted files may also have high entropy, while ransomware can modify its behaviour to avoid detection. New and modified ransomware may also be difficult for traditional signature-based detection to identify.

Therefore, multiple behavioural indicators need to be combined with machine learning to improve ransomware detection and classification.

### Problem 2: Limited Generalisation to Realistic Windows Endpoint Environments

Many machine-learning-based ransomware studies report high detection performance using controlled, synthetic or sandbox datasets. However, these environments may not fully represent realistic Windows endpoints containing legitimate applications, background processes and normal user activities.

Detection performance may also differ when models trained on controlled datasets are applied to actual endpoint behaviour. Therefore, the proposed detection approach needs to be considered under more realistic Windows endpoint conditions and against different ransomware behaviours.

---

## 5. Research Aim

To create and assess a machine-learning-based behavioural detection method for identifying file-encrypting ransomware on Windows endpoints while considering dataset quality, generalisation and realistic endpoint validation.

---

## 6. Research Objectives

### RO1

To identify and analyse behavioural characteristics associated with file-encrypting ransomware on Windows endpoints.

### RO2

To develop a machine-learning-based method using selected behavioural characteristics to distinguish ransomware-related and legitimate endpoint activities.

### RO3

To assess the effectiveness of the proposed behavioural detection method using suitable classification and detection metrics.

---



\## 7. Proposed Solution



The proposed solution is a behaviour-based ransomware detection approach for Windows endpoints.



The approach will analyse multiple behavioural characteristics instead of relying on a single indicator. The selected characteristics may include:

- File-system activity

- File-writing activity

- File renaming and extension changes

- File entropy changes

- Process behaviour

- API behaviour

These behavioural features will be used in a supervised machine-learning approach to distinguish legitimate endpoint activities from ransomware-related activities.

The proposed approach will consider machine-learning algorithms such as:

- Random Forest

- XGBoost

- Support Vector Machine (SVM)

The final model selection will be based on the findings from the literature review, dataset suitability and evaluation results.

---

## 8. Research Methodology

The research will follow a systematic research process consisting of:

1. Literature review and identification of research gaps

2. Identification of ransomware behavioural characteristics

3. Dataset selection and preparation

4. Behavioural feature selection and preprocessing

5. Machine-learning model development

6. Model testing and evaluation

7. Analysis of detection performance

8. Discussion of findings and limitations

The methodology will focus on developing and evaluating a machine-learning-based behavioural detection approach rather than a complete commercial Endpoint Detection and Response (EDR) system.

---

## 9. Development Model

**Development Model:** Machine Learning Development Life Cycle (MLDLC) / Iterative CRISP-DM
The system is developed following a 5-phase iterative engineering lifecycle:
1. **Endpoint Domain Understanding:** Formulating behavioural ransomware attack vectors and normal user profiles.
2. **Data & Telemetry Ingestion:** Continuous Sysmon log monitoring and file-system event buffering.
3. **Feature Engineering & Preprocessing:** 5-second temporal sliding windows, Shannon entropy calculation, delta tracking, and robust feature standardization.
4. **Ensemble Model Training & Validation:** Training Random Forest, XGBoost, and SVM with 5-fold cross-validation and soft probability voting.
5. **Real-Time Evaluation & Mitigation:** Threshold-based risk classification (`Benign`, `Suspicious`, `Ransomware`) and alerting.

---

## 10. Research Scope

The research focuses on:
- File-encrypting ransomware
- Windows endpoint environments
- Behaviour-based ransomware detection
- Process/API behaviour
- Entropy changes
- File writing and renaming
- File-system activity
- Supervised machine learning
- Random Forest
- XGBoost
- Support Vector Machine (SVM)
- Classification of legitimate and ransomware-related activities
- Detection performance evaluation

The research focuses on ransomware detection and classification and does not aim to develop a complete commercial EDR solution.

---

## 11. Proposed System Architecture

The proposed system follows a behavioural detection pipeline:

```text
Windows Endpoint Activity
          ↓
Behavioural Data Collection (Sysmon & Entropy Monitor)
          ↓
Feature Extraction (5-Second Sliding Window)
          ↓
Data Preprocessing & Scaling (StandardScaler)
          ↓
Behavioural Feature Vector (8 Metrics)
          ↓
Machine Learning Multi-Model Ensemble (RF, XGBoost, SVM)
          ↓
Classification & Threat Taxonomy
     ↙         ↓          ↘
 Benign    Suspicious   Ransomware
 (<0.40)  (0.40-0.79)    (≥0.80)
     ↓         ↓          ↓
  Permit     Audit      Alert & Mitigate
```

---

## 12. Repository Structure

| Folder | Contents |
| :--- | :--- |
| [`01_Research_Papers/`](01_Research_Papers/) | Summary of foundational research papers and identified research gaps |
| [`02_Literature_Review/`](02_Literature_Review/) | In-depth literature review, attack tactics, and algorithm comparative analysis |
| [`03_Architecture_and_Flowchart/`](03_Architecture_and_Flowchart/) | System architecture diagrams, flowchart specifications, and design layers |
| [`04_Source_Code/`](04_Source_Code/) | Production source code: monitoring, feature extraction, ML models, and pipeline runner |
| [`05_Data_or_Sample_Input/`](05_Data_or_Sample_Input/) | Synthetic dataset (1,500 samples) and raw sample Sysmon endpoint logs |
| [`06_Result_or_Expected_Outcome/`](06_Result_or_Expected_Outcome/) | Model evaluation metrics, literature benchmarks, and classification outputs |
| [`07_References/`](07_References/) | Full academic bibliography in IEEE and APA formats |

---

## 13. Quick Start & Execution Guide

### 1. Install Dependencies
```bash
cd 04_Source_Code
pip install -r requirements.txt
```

### 2. Run the End-to-End Pipeline
```bash
python run_pipeline.py
```
This single command:
1. Generates/loads the 1,500-instance behavioural dataset (`05_Data_or_Sample_Input/synthetic_features_dataset.csv`).
2. Trains and cross-validates Random Forest, SVM, XGBoost, and the Multi-Model Soft Voting Ensemble.
3. Saves the trained models in `04_Source_Code/saved_models/`.
4. Saves evaluation metrics to `06_Result_or_Expected_Outcome/model_evaluation_metrics.json`.
5. Executes a live endpoint telemetry simulation demonstrating real-time threat classification and alert generation.