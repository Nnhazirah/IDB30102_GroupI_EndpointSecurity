# 03_Architecture_and_Flowchart

## Purpose
This folder contains architectural diagrams and flowcharts for the ransomware detection system. These diagrams are consistent with Chapter 3 of the Research Proposal.

## [Files](File.md)

| File | Description |
|------|-------------|
| architecture_diagram.png | System architecture showing all components |
| system_flowchart.png | Step-by-step process flow |

## [Architecture_Diagram](Architecture_Diagram.md)

<img width="2720" height="2120" alt="ransomware_detection_architecture" src="https://github.com/user-attachments/assets/84eb39f9-5e2a-4f9f-8e9a-f2c301df30c5" />

Figure 3.1 shows the proposed system architecture organized into four layers:

Layer 1: Data Collection - Collects endpoint data from Sysmon telemetry, API calls, File I/O operations, and entropy monitoring. Based on Ramamoorthi et al. (2026), Abdelwahed et al. (2023), and Lee & Lee (2022).

Layer 2: Feature Extraction - Extracts behavioral features including write velocity (Ahmed R et al., 2026), entropy change (Amoruso et al., 2026), rename frequency, and directory coverage (Hou et al., 2024).

Layer 3: Detection Engine - Uses ensemble of Random Forest (98.1% accuracy, Elsersy et al., 2024), XGBoost (98.5% accuracy, Muppidi & Sureshkumar, 2025), and SVM (97.3% precision, Zirari et al., 2025) with soft/hard voting (Surya & Sivakumar, 2024).

Layer 4: Output & Response - Generates alerts with confidence scores and risk levels, and provides dashboard metrics.

## [System_Flowchart](System_Flowchart.md)

<img width="2720" height="2112" alt="ransomware_detection_pipeline_overview" src="https://github.com/user-attachments/assets/89e51a86-54ef-4bf5-82e7-cb23b599f580" />

<img width="2720" height="1880" alt="ransomware_detection_response_branching" src="https://github.com/user-attachments/assets/d17ad1f9-7e7d-44e5-a44f-84f88c624e5d" />

Figure 3.2 shows the complete system process flow. The system starts by monitoring the endpoint using multiple data sources. Events are collected using a 5-second sliding window based on Ahmed R et al. (2026). Features are extracted and three ML models are applied. Predictions are combined using ensemble voting (Surya & Sivakumar, 2024). Classification is based on confidence thresholds: Benign (>0.8), Suspicious (0.4-0.8), and Ransomware (>0.8). For detected ransomware, the system generates alerts, terminates processes, and isolates endpoints.

## [Consistency](Consistency.md)
These diagrams align with Chapter 3, Sections 3.4 and 3.5 of the Research Proposal.
