# 04_Source_Code - Ransomware Detection Prototype

## Overview
This folder contains preliminary source code for the ransomware detection system proposed in our research. The code demonstrates the feasibility of the proposed approach.

## Project Structure

| Folder/File | Description |
|-------------|-------------|
| `agent/` | Detection agent that runs on Windows endpoints |
| `requirements.txt` | Python dependencies |

## Technologies Used

| Component | Technology |
|-----------|------------|
| Agent | Python 3.8+, pywin32 |
| Model | Scikit-learn (Random Forest) |

## Setup Instructions

```bash
# Install dependencies
pip install -r requirements.txt

# Run agent (Windows only)
python agent/agent_main.py

5. Scroll down, write commit message: `Added 04_Source_Code README`
6. Select **"Commit directly to the main branch"**
7. Click **"Commit new file"**

---

### STEP 2: Create agent/__init__.py

1. Click **"Add file"** → **"Create new file"**

2. File name:

3. Paste:
```python
"""
Agent package for ransomware detection
"""
__version__ = "0.1.0"
