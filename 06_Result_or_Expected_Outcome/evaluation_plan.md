# Proposed Evaluation Plan

The proposed system will be evaluated to determine whether multiple behavioural features combined with machine learning can effectively detect file-encrypting ransomware on Windows endpoints.

## Baseline Models

The following individual models will be evaluated:

- Random Forest
- XGBoost
- Support Vector Machine (SVM)

Their performance will be compared with the proposed ensemble model.

## Test Environment

The evaluation will consider:

- Benign Windows endpoint activities
- Ransomware-related activities
- Normal user activities
- Simulated ransomware behaviour
- Controlled Windows endpoint environment

## Evaluation Metrics

The proposed detection method will be evaluated using:

- Accuracy
- Precision
- Recall
- F1-score
- False Positive Rate (FPR)
- Detection Response Time

## Target Performance

The proposed targets are:

- Accuracy > 95%
- F1-score > 0.95
- False Positive Rate < 5%
- Response Time < 5 seconds

The results will be compared between the individual machine learning models and the proposed ensemble model.
