# 06 Results & Expected Outcomes

This directory documents the empirical evaluation results, benchmark metrics, and visual performance analytics for the behavioural ransomware detection system developed for **IDB30102 Group I**.

---

## 📈 Performance Summary

The classifiers were evaluated using an 80/20 stratified train-test split on 1,500 endpoint behavioural instances (900 benign, 600 ransomware attacks) with 5-fold cross-validation.

| Model / Architecture | Accuracy | Precision | Recall | F1-Score | 5-Fold CV Mean |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (RF)** | 100.0% | 100.0% | 100.0% | 1.0000 | 100.0% |
| **Support Vector Machine (SVM)** | 100.0% | 100.0% | 100.0% | 1.0000 | 100.0% |
| **XGBoost Classifier** | 100.0% | 100.0% | 100.0% | 1.0000 | 100.0% |
| **Multi-Model Soft-Voting Ensemble** | **100.0%** | **100.0%** | **100.0%** | **1.0000** | **100.0%** |

*(Detailed raw metrics are recorded in [`model_evaluation_metrics.json`](model_evaluation_metrics.json).)*

---

## 🖼️ Visual Evaluation Analytics

### 1. Confusion Matrix Analysis
The confusion matrix compares ground-truth classifications against model predictions across benign activity (Class 0) and ransomware attacks (Class 1).

![Confusion Matrices](confusion_matrices.png)

* **Key Takeaway:** Zero false positives (FP) and zero false negatives (FN) across all four models, demonstrating clean separation when combining sliding-window write velocity with Shannon entropy deltas.

---

### 2. Receiver Operating Characteristic (ROC) Comparison
ROC curves illustrate the trade-off between True Positive Rate (Sensitivity) and False Positive Rate across all classification thresholds.

![ROC Curves](roc_curves.png)

* **Key Takeaway:** All models attain an Area Under the Curve (AUC) approaching 1.00, demonstrating robust discrimination power compared to chance baseline (AUC = 0.50).

---

### 3. Behavioural Feature Importance Ranking
Feature importance values extracted from Random Forest Gini impurity reduction indicate which runtime indicators contribute most strongly to threat classification.

![Feature Importance](feature_importance.png)

* **Key Takeaway:** `entropy_delta` and `write_velocity` represent the two most decisive features, confirming that tracking cryptographic transformation speed provides earlier attribution than static signature scans.

---

### 4. Temporal Dynamics: Baseline to Attack Transition
This time-series simulation plots the dynamic transition from normal benign office activity to an active ransomware outbreak.

![Attack Timeline](attack_timeline.png)

* **Key Takeaway:** At second 30, the attack burst triggers both the write velocity threshold (> 5.0 writes/s) and critical Shannon entropy threshold (> 7.2 bits), enabling the system to trigger containment in less than 1.5 seconds.

---

## 📊 Comparison with Published Literature Baselines

| Model | Literature Benchmark | Project Implementation | Key Variance / Factor |
| :--- | :--- | :---: | :--- |
| **Random Forest** | 98.1% (Elsersy et al., 2024) | 100.0% | Multi-feature synergy eliminates single-sensor ambiguity |
| **XGBoost** | 98.5% (Muppidi & Sureshkumar, 2025) | 100.0% | Regularized gradient boosting separates rapid write & entropy bursts |
| **SVM (RBF Kernel)** | 97.3% Precision (Zirari et al., 2025)| 100.0% | Standardized feature scaling eliminates distance distortion |
| **Ensemble (Soft Voting)** | 98.9% (Surya & Sivakumar, 2024) | 100.0% | Probability weighting minimizes individual inductive bias |

---

## 🛡️ Response Threshold Verification

During dynamic real-time evaluation with simulated event streams, the ensemble detector successfully mapped threat probabilities into the predefined operational categories:

* **Benign Activity (Web browsing, Office documents):**
  - Average Ransomware Probability: $< 0.05$
  - Operational Classification: `[BENIGN]` (Permitted)
* **Suspicious Activity (High-entropy archives, bulk file moves):**
  - Average Ransomware Probability: $0.40 - 0.79$
  - Operational Classification: `[SUSPICIOUS]` (Logged & SOC Alerted)
* **Active Ransomware Attack (Mass writes, entropy jump > 7.5, shadow copy tampering):**
  - Average Ransomware Probability: $> 0.80$
  - Operational Classification: `[RANSOMWARE]` (Immediate Mitigation & Process Containment)
