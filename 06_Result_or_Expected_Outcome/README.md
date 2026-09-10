# 06 Results & Expected Outcomes

This directory documents the evaluation results, benchmark metrics, and performance comparisons of the behavioural ransomware detection models developed for **IDB30102 Group I**.

---

## 📈 Performance Summary

The classifiers were evaluated using an 80/20 stratified train-test split on 1,500 endpoint behavioural instances (900 benign, 600 ransomware attacks) with 5-fold cross-validation.

| Model / Architecture | Accuracy | Precision | Recall | F1-Score | 5-Fold CV Mean |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest (RF)** | 100.0% | 100.0% | 100.0% | 1.0000 | 100.0% |
| **Support Vector Machine (SVM)** | 100.0% | 100.0% | 100.0% | 1.0000 | 100.0% |
| **XGBoost Classifier** | 100.0% | 100.0% | 100.0% | 1.0000 | 100.0% |
| **Multi-Model Soft-Voting Ensemble** | **100.0%** | **100.0%** | **100.0%** | **1.0000** | **100.0%** |

*(Detailed raw metrics are recorded in [`model_evaluation_metrics.json`](model_evaluation_metrics.json).)*

---

## 📊 Comparison with Published Literature Baselines

| Model | Literature Benchmark | Project Implementation | Key Variance / Factor |
| :--- | :--- | :--- | :--- |
| **Random Forest** | 98.1% (Elsersy et al., 2024) | 100.0% (Synthetic) | Controlled behavioural boundaries with multi-feature synergy |
| **XGBoost** | 98.5% (Muppidi & Sureshkumar, 2025) | 100.0% (Synthetic) | Regularized gradient boosting separates rapid write & entropy bursts |
| **SVM (RBF Kernel)** | 97.3% Precision (Zirari et al., 2025)| 100.0% (Synthetic) | Standardized feature scaling eliminates distance distortion |
| **Ensemble (Soft Voting)** | 98.9% (Surya & Sivakumar, 2024) | 100.0% (Synthetic) | Probability weighting minimizes single-model edge errors |

---

## 🎯 Evaluation Metrics & Formulas

1. **Accuracy:**
   $$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$
2. **Precision (Positive Predictive Value):**
   $$\text{Precision} = \frac{TP}{TP + FP}$$
3. **Recall (Detection Rate / True Positive Rate):**
   $$\text{Recall} = \frac{TP}{TP + FN}$$
4. **F1-Score (Harmonic Mean):**
   $$F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

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
  - Operational Classification: `[RANSOMWARE]` (Immediate Mitigation)
