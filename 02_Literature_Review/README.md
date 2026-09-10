# 02 Literature Review: Behavioural Ransomware Detection

This directory contains the synthesis of existing literature, comparative analysis of detection paradigms, and review of machine learning algorithms applied to endpoint ransomware detection on Windows operating systems.

---

## 1. Evolution of File-Encrypting Ransomware

File-encrypting ransomware (cryptoviral extortion) remains one of the most destructive threats facing modern enterprise and consumer endpoints. Contemporary ransomware families (such as *LockBit*, *BlackCat/ALPHV*, *REvil*, and *WannaCry*) exhibit structured multi-stage execution phases:

1. **Initial Access & Privilege Escalation:** Execution via phishing, vulnerability exploitation, or compromised credentials.
2. **Defense Evasion & Discovery:** Disabling Windows Defender, unhooking security tools, and enumerating drives/shares.
3. **Recovery Sabotage:** Deleting Volume Shadow Copies (`vssadmin delete shadows /all /quiet`), disabling Windows Error Recovery (`bcdedit /set {default} bootstatuspolicy ignoreallfailures`), and deleting backup catalogs (`wbadmin delete catalog -quiet`).
4. **Mass Traversal & Encryption:** Rapid traversal across directories, reading documents, encrypting with symmetric algorithms (AES/ChaCha20), appending ransomware extensions, and writing high-entropy ciphertext.
5. **Ransom Note Generation:** Dropping ransom notes in affected directories and alerting the victim.

---

## 2. Comparison of Detection Paradigms

| Parameter | Signature-Based (AV) | Heuristic-Based | Behavioural ML (Proposed) |
| :--- | :--- | :--- | :--- |
| **Detection Basis** | Known file hashes, byte patterns, YARA rules | Static rule checks, API import tables | Dynamic endpoint activity, runtime metrics, entropy |
| **Zero-Day Resilience** | Very Poor (fails on new hashes) | Moderate (can be bypassed via packing) | **High** (detects malicious operational behavior) |
| **Obfuscation Resistance** | Vulnerable to polymorphism/packing | Vulnerable to code mutation | **Robust** (focuses on observable OS impact) |
| **False Positive Rate** | Minimal on known binaries | Moderate | Low when multi-feature ensemble is applied |
| **Latency** | Instantaneous lookup | Fast | Real-time sliding window (sub-second) |

---

## 3. Analysis of Behavioural Indicators

### A. File I/O Velocity & Modification Count
Ransomware must encrypt as many user documents as possible before containment occurs. Consequently, ransomware exhibits anomalous **write velocities** (e.g., 10–50+ file writes per second), whereas normal user applications rarely exceed 1–2 writes per second during routine office or browsing activities.

### B. Shannon Entropy & Entropy Delta
Information entropy measures the degree of randomness in a byte stream (0.0 to 8.0 bits for bytes):
$$H(X) = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i)$$
- **Plaintext / Code files:** typically range between 2.5 and 5.5 bits.
- **Encrypted ciphertext / Packed data:** exceeds 7.2 bits (often 7.6–7.99 bits).
- **Entropy Delta:** Sudden jumps ($\Delta H > 1.5$) during file overwrites serve as strong indicators of cryptographic transformation.

### C. Mass Rename & Extension Manipulation
Ransomware systematically appends unique extensions to encrypted files (e.g., `.locked`, `.enc`, `.wnry`). Tracking rename rates within a sliding window provides early warning prior to total disk encryption.

### D. System Recovery Interference
Ransomware actively invokes native Windows system utilities to hinder rollback:
- `vssadmin.exe delete shadows /all /quiet`
- `wmic shadowcopy delete`
- `bcdedit /set {default} recoveryenabled No`
Detecting these command-line invocations or associated process trees provides near-certain malicious attribution.

---

## 4. Machine Learning Classification Algorithms

### 1. Random Forest (RF)
- **Mechanism:** Ensemble of de-correlated decision trees using bagging and random feature subspaces.
- **Strengths:** Handles non-linear feature interactions, resistant to overfitting, provides built-in feature importance ranking.
- **Literature Benchmark:** 98.1% accuracy on endpoint logs (Elsersy et al., 2024).

### 2. Extreme Gradient Boosting (XGBoost)
- **Mechanism:** Scalable end-to-end tree boosting algorithm utilizing second-order gradient approximations and regularization ($L_1/L_2$).
- **Strengths:** Exceptional speed, robust handling of sparse behavioral features, high precision.
- **Literature Benchmark:** 98.5% accuracy (Muppidi & Sureshkumar, 2025).

### 3. Support Vector Machine (SVM)
- **Mechanism:** Constructs optimal maximum-margin separating hyperplanes using Radial Basis Function (RBF) kernel mapping.
- **Strengths:** Highly effective in high-dimensional feature spaces with clear margins of separation when features are standardized.
- **Literature Benchmark:** 97.3% precision (Zirari et al., 2025).

### 4. Multi-Model Ensemble Voting
- **Soft Voting:** Computes the probability average across RF, XGBoost, and SVM, yielding superior confidence calibration.
- **Literature Benchmark:** Demonstrates increased resilience against single-model bias, achieving higher stability and generalization (Surya & Sivakumar, 2024).
