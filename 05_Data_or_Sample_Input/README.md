# 05 Data & Sample Input

This directory contains the dataset files and sample raw endpoint telemetry logs used to train, test, and validate the behavioural ransomware detection models.

---

## 📁 Files in this Directory

| Filename | Format | Description |
| :--- | :--- | :--- |
| `synthetic_features_dataset.csv` | CSV | 1,500 labeled feature vectors (900 benign, 600 ransomware) for ML model training and validation. |
| `sample_endpoint_logs.json` | JSON | 100 raw simulated Sysmon endpoint events (50 benign, 50 ransomware attack events) for pipeline testing. |

---

## 📊 Dataset Schema (`synthetic_features_dataset.csv`)

The dataset contains the 8 behavioural features extracted over 5-second sliding windows, followed by the ground-truth classification target:

| Feature Name | Type | Range / Units | Description | Benign Baseline | Ransomware Baseline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `write_velocity` | Float | writes/sec ($\ge 0$) | File write operations per second | Low ($0.1 - 4.0$) | High ($15.0 - 65.0$) |
| `entropy_current` | Float | $0.0 - 8.0$ bits | Shannon entropy of modified files | Normal ($2.0 - 5.5$), Archives ($7.0 - 7.5$) | Very High ($7.5 - 7.99$) |
| `entropy_delta` | Float | $\Delta$ bits | Change in entropy before & after write | Stable ($-0.5$ to $+0.8$) | Surge ($+1.8$ to $+5.0$) |
| `rename_rate` | Float | renames/sec ($\ge 0$) | Frequency of file renaming / extension change | Minimal ($0.0 - 0.2$) | Rapid ($3.0 - 25.0$) |
| `directory_coverage` | Integer | count ($\ge 1$) | Distinct directories modified in window | Localized ($1 - 3$) | Traversal ($5 - 25$) |
| `api_call_frequency` | Float | calls/sec | Frequency of file/crypto/system API calls | Moderate ($2.0 - 20.0$) | Extreme ($40.0 - 150.0$) |
| `shadow_copy_attempt`| Integer | Binary ($0$ or $1$) | Invocations of `vssadmin`, `bcdedit`, `wmic` | None ($0$) | Sabotage ($1$) |
| `file_count_modified`| Integer | count ($\ge 1$) | Cumulative file count modified | Minimal ($1 - 35$) | Massive ($80 - 1500$) |
| `label` | Integer | Binary ($0$ or $1$) | Ground-truth target | $0$ (Benign Activity) | $1$ (Ransomware Attack) |

---

## ⚙️ How to Regenerate Dataset

To re-synthesize or customize the dataset:
```bash
python -c "from run_pipeline import generate_synthetic_dataset; df = generate_synthetic_dataset(2000); df.to_csv('synthetic_features_dataset.csv', index=False); print('Dataset updated!')"
```
Or simply run the main pipeline:
```bash
python ../04_Source_Code/run_pipeline.py
```
