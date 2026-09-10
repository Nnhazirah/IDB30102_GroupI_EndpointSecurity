# 04 Source Code: Endpoint Security System

This directory contains the complete source code for the IDB30102 Group 1 Endpoint Security project. The code is organized into three main modules: data preprocessing, machine learning model detection, and system monitoring.

## 📂 Directory Structure

*   **`preprocessing/`**: Scripts to clean, format, and extract features from raw data.
    *   `feature_extraction.py`: Extracts relevant features from raw logs to be used by the detection models.
*   **`detection/`**: Machine learning models and algorithms used to identify security threats.
    *   `random_forest_model.py`: Implementation of the Random Forest classifier.
    *   `svm_model.py`: Implementation of the Support Vector Machine (SVM) classifier.
    *   `xgboost_model.py`: Implementation of the XGBoost classifier.
    *   `ensemble_detector.py`: Combines predictions from the individual models to improve overall detection accuracy.
*   **`monitoring/`**: Scripts for real-time system observation and data collection.
    *   `sysmon_collector.py`: Collects system activity logs using Sysmon.
    *   `entropy_analyzer.py`: Analyzes data entropy to detect potentially encrypted, packed, or malicious files.

## ⚙️ Prerequisites

Ensure you have Python installed on your system. The required third-party libraries and dependencies for this project are listed in the `requirements.txt` file.

## 🚀 Setup and Installation

1. **Navigate to the source code directory:**
   ```bash
   cd 04_Source_Code
