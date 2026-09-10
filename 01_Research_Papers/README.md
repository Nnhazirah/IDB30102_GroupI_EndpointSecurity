# 01 Research Papers: Endpoint Security & Behavioural Ransomware Detection

This directory documents the core research papers, scholarly literature, and empirical baselines that form the foundation for the **IDB30102 Group I** research project on behavioural detection of file-encrypting ransomware on Windows endpoints.

---

## 📚 Key Research Papers & Theoretical Foundations

| Ref ID | Authors & Year | Paper Title / Focus | Key Contribution to Project |
|---|---|---|---|
| **RP-01** | Ramamoorthi et al. (2026) | *Endpoint Telemetry and Sysmon Monitoring for Advanced Threat Detection* | Architectural foundation for Layer 1 data ingestion using Windows Sysmon event telemetry. |
| **RP-02** | Abdelwahed et al. (2023) | *Dynamic Behavioural Analysis of Ransomware via System API Interception* | Identified critical API calls (e.g., `CryptEncrypt`, `NtWriteFile`, `MoveFileExW`) and process spawning patterns. |
| **RP-03** | Lee & Lee (2022) | *Multi-Vector Ransomware Defense: Combining File I/O and Entropy Metrics* | Established the necessity of combining structural file metrics with process telemetry. |
| **RP-04** | Ahmed R. et al. (2026) | *Sliding Window Feature Extraction for Rapid Ransomware Identification* | Defined the 5-second sliding window technique and write-velocity metric calculation. |
| **RP-05** | Amoruso et al. (2026) | *Shannon Entropy Dynamics in File-Encrypting Malware on Windows* | Provided threshold criteria for detecting encryption (Shannon entropy > 7.2 bits and sudden positive delta). |
| **RP-06** | Hou et al. (2024) | *Graph and Traversal Analysis of Mass File Renaming in Ransomware Families* | Established rename rate and directory coverage metrics to capture rapid file-system traversal. |
| **RP-07** | Elsersy et al. (2024) | *Ransomware Classification on Windows Endpoints using Random Forest Ensembles* | Demonstrated baseline 98.1% detection accuracy using decision tree ensembles on endpoint logs. |
| **RP-08** | Muppidi & Sureshkumar (2025) | *Extreme Gradient Boosting (XGBoost) for Zero-Day Endpoint Threat Detection* | Showed 98.5% accuracy with low false positive rates using gradient boosted decision trees. |
| **RP-09** | Zirari et al. (2025) | *Support Vector Machines with RBF Kernel for Endpoint Behavioural Classification* | Achieved 97.3% precision in separating non-linear behavioral distributions using scaled features. |
| **RP-10** | Surya & Sivakumar (2024) | *Ensemble Voting Architectures for Robust Endpoint Security and Threat Mitigation* | Provided the soft and hard voting ensemble framework combining RF, XGBoost, and SVM. |

---

## 🎯 Research Gaps Identified from Papers

1. **Reliance on Static Signatures:** Traditional antivirus solutions fail against novel zero-day variants, obfuscated payloads, and polymorphic ransomware.
2. **Synthetic / Sandbox Dataset Limitations:** Existing machine learning models often overfit on controlled sandbox datasets and struggle in realistic Windows endpoints containing legitimate high-entropy files (compressed archives, media) and high-volume background processes.
3. **Single-Indicator Vulnerability:** Relying purely on file entropy causes false positives on archiving software (e.g., 7-Zip, WinRAR), while relying purely on write speed causes false positives on file backups or system updates.
4. **Ensemble Multi-Vector Solution:** Combining write velocity, Shannon entropy deltas, rename frequency, directory coverage, recovery tampering (shadow copy deletion), and machine learning voting overcomes individual sensor limitations.
