# 03 Architecture and Flowchart Specifications

This directory contains the system architecture blueprints, process flowcharts, and component design specifications for the **IDB30102 Group I** endpoint ransomware detection system.

---

## 📄 Architecture Documentation

* **[`Proposed_System_Architecture.md`](Proposed_System_Architecture.md):** Detailed technical specification of the four-tier architectural model, telemetry pipelines, and mitigation thresholds.

---

## 🏛️ System Architecture Diagram

<img width="100%" alt="System Architecture Overview" src="https://github.com/user-attachments/assets/84eb39f9-5e2a-4f9f-8e9a-f2c301df30c5" />

### Layer Breakdown:

* **Layer 1: Data Collection & Sensor Watchdogs**  
  Captures real-time endpoint telemetry using Windows Sysmon event telemetry (Event IDs 1, 11, 23), active Shannon file entropy tracking, file-system I/O hooks, and recovery tampering observers (Ramamoorthi et al., 2026; Abdelwahed et al., 2023; Lee & Lee, 2022).

* **Layer 2: Behavioural Feature Extraction**  
  Aggregates incoming event streams across a 5-second sliding temporal window to calculate write velocity, entropy deltas, rename frequency, directory coverage, and API frequencies (Ahmed et al., 2026; Amoruso et al., 2026; Hou et al., 2024).

* **Layer 3: Machine Learning Detection Engine**  
  Features are normalized using `StandardScaler` and passed into an ensemble composed of Random Forest (Elsersy et al., 2024), XGBoost (Muppidi & Sureshkumar, 2025), and SVM (Zirari et al., 2025). Predictions are synthesized using a calibrated probability soft-voting mechanism (Surya & Sivakumar, 2024).

* **Layer 4: Threat Classification & Response**  
  Applies risk thresholds to classify events into `[BENIGN]` ($<0.40$), `[SUSPICIOUS]` ($0.40-0.79$), or `[RANSOMWARE]` ($\ge 0.80$), generating real-time alerts on the CustomTkinter desktop dashboard and initiating defensive containment.

---

## 🔄 System Process Flowcharts

<img width="100%" alt="Ransomware Detection Pipeline Flowchart" src="https://github.com/user-attachments/assets/89e51a86-54ef-4bf5-82e7-cb23b599f580" />

<img width="100%" alt="Response Branching Logic Flowchart" src="https://github.com/user-attachments/assets/d17ad1f9-7e7d-44e5-a44f-84f88c624e5d" />

### Operational Workflow:
1. **Telemetry Ingestion:** Endpoint activities are continuously monitored across file system and process vectors.
2. **Temporal Windowing:** A 5-second sliding window prevents memory bloat while preserving transient attack characteristics.
3. **Feature Computation:** Eight dynamic metrics are extracted and standardized.
4. **Ensemble Voting:** Calibrated predictions from Random Forest, XGBoost, and SVM are averaged.
5. **Mitigation Branching:** High-confidence detections ($\ge 0.80$) trigger process suspension, host network isolation, and SOC administrator notification.

---

## 📑 Proposal Consistency

These specifications correspond directly to Chapter 3 (Methodology & System Architecture, Sections 3.4 and 3.5) of the Group I Research Proposal.
