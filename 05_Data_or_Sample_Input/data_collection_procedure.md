# Data Collection Procedure

The proposed research focuses on collecting behavioural information from Windows endpoints for ransomware detection.

## Data Sources

The proposed data collection uses:

- Sysmon telemetry
- API call information
- File I/O activity
- File entropy

## Behavioural Activities

Two categories of endpoint activities are considered.

### Benign Activities

- Opening files
- Reading files
- Writing and modifying files
- Copying files
- Normal application activities

### Ransomware-Related Activities

- Rapid file modification
- Repeated file renaming
- Significant entropy changes
- Suspicious process and file interactions
- Recovery-related activities

## Feature Extraction

The collected events are organised using a 5-second sliding window.

The main behavioural features include:

- Write velocity
- Entropy change
- Rename frequency
- Directory coverage
- API call patterns
- Shadow copy attempts

The collected data will be labelled as benign or ransomware-related and prepared for model training and testing.
