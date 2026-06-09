# SOC Dashboard Demo

## Overview

This directory contains the SOC dashboard demo for the MITRE ATT&CK prediction project.

The dashboard provides an interactive interface for analyzing Windows/Sysmon events using:

* FastAPI backend
* JavaScript frontend
* Hierarchical ML classifier
* Local Ollama/Qwen LLM explanation

The dashboard is designed for demonstration purposes. It allows users to load built-in example alerts, run ATT&CK prediction, and view SOC-friendly explanations.

---

## Dashboard Workflow

```text
Sysmon Event Input
        ↓
Feature Normalization
        ↓
Hierarchical ML Classifier
        ↓
ATT&CK Prediction
        ↓
Qwen LLM Explanation
        ↓
SOC Dashboard Output
```

---

## Features

The dashboard supports:

```text
Built-in demo alerts
Sysmon event input
ATT&CK parent-technique prediction
ATT&CK sub-technique prediction
Confidence score
Top-k ATT&CK candidate labels
Technique name display
LLM-generated SOC explanation
Triage priority
Recommended investigation steps
False-positive checks
Splunk search ideas
```

---

## Directory Structure

```text
soc_dashboard/
├── app.py
├── ml_predict_then_llm_explain.py
└── static/
    ├── index.html
    ├── app.js
    └── style.css
```

The dashboard depends on trained ML models stored in the project-level `models/` directory:

```text
models/
├── tfidf_sgd_parent.joblib
└── tfidf_sgd_subtechnique.joblib
```

---

## System Requirements

### Python Packages

Install the required packages:

```bash
pip install fastapi uvicorn requests joblib numpy pandas scikit-learn
```

### Ollama

The dashboard uses Ollama for local LLM explanations.

Install Ollama and pull the model:

```bash
ollama pull qwen2.5:3b-instruct
```

Check available models:

```bash
ollama list
```

Start Ollama:

```bash
ollama serve
```

The expected model name in the code is:

```python
OLLAMA_MODEL = "qwen2.5:3b-instruct"
```

---

## Required ML Models

Before running the dashboard, make sure these files exist:

```text
models/tfidf_sgd_parent.joblib
models/tfidf_sgd_subtechnique.joblib
```

If they do not exist, go back to the project root and run:

```bash
python 05_train_event_hierarchical_classical_ml.py
```

---

## Configuration

Open:

```text
soc_dashboard/ml_predict_then_llm_explain.py
```

Check the model paths.

If you run the dashboard from inside `soc_dashboard/`, use:

```python
PARENT_MODEL_PATH = "../models/tfidf_sgd_parent.joblib"
SUB_MODEL_PATH = "../models/tfidf_sgd_subtechnique.joblib"
```

Check the Ollama configuration:

```python
OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:3b-instruct"
```

---

## How to Run

From the project root:

```bash
cd soc_dashboard
python3 app.py
```

Then open:

```text
http://localhost:8000
```

For a remote server:

```text
http://<server-ip>:8000
```

---

## Alternative Run Command

You can also run the dashboard using Uvicorn directly:

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

If running from the project root:

```bash
uvicorn soc_dashboard.app:app --host 0.0.0.0 --port 8000 --reload
```

---

## Demo Workflow

1. Open the dashboard in a browser.
2. Select a built-in demo alert.
3. Click **Load Example**.
4. Click **Analyze Alert**.
5. Review:

   * Final ATT&CK prediction
   * Technique name
   * Confidence score
   * Parent and sub-technique candidates
   * LLM explanation
   * Triage priority
   * Recommended steps
   * Splunk search ideas

---

## Example Demo Alert

```text
EventID=1
Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine=powershell.exe -nop -w hidden -enc SQBFAFgA...
ParentImage=C:\Windows\System32\cmd.exe
ParentCommandLine=cmd.exe /c powershell.exe -enc SQBFAFgA...
User=corp\alice
Computer=win10-01
```

Expected behavior:

```text
ATT&CK prediction
Confidence score
Technique name
LLM SOC explanation
Triage recommendations
Splunk search ideas
```

---

## API Endpoints

### Health Check

```text
GET /api/health
```

### Get Demo Examples

```text
GET /api/examples
```

### Analyze Event

```text
POST /api/analyze
```

Example request:

```json
{
  "EventID": "1",
  "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
  "ParentImage": "C:\\Windows\\System32\\cmd.exe",
  "ParentCommandLine": "cmd.exe /c powershell.exe -enc SQBFAFgA...",
  "User": "corp\\alice",
  "Computer": "win10-01"
}
```

---

## Troubleshooting

### Ollama connection error

Check whether Ollama is running:

```bash
curl http://localhost:11434/api/tags
```

If it fails, start Ollama:

```bash
ollama serve
```

---

### Model file not found

Check that the required model files exist:

```bash
ls ../models/
```

Required files:

```text
tfidf_sgd_parent.joblib
tfidf_sgd_subtechnique.joblib
```

If missing, run from the project root:

```bash
python 05_train_event_hierarchical_classical_ml.py
```

---

### Static files not loading

Check that the frontend files exist:

```bash
ls static/
```

Expected files:

```text
index.html
app.js
style.css
```

---

### Port already in use

Run with another port by editing `app.py`:

```python
uvicorn.run(
    "app:app",
    host="0.0.0.0",
    port=8080,
    reload=True
)
```

Then open:

```text
http://localhost:8080
```

---

## Presentation Demo Script

Use this order during presentation:

```text
1. Explain the raw Sysmon event.
2. Load a built-in demo alert.
3. Click Analyze Alert.
4. Explain the ML prediction and confidence score.
5. Explain top-k ATT&CK candidates.
6. Show the LLM SOC explanation.
7. Highlight recommended triage steps.
8. Show Splunk search suggestions.
9. Explain how this reduces analyst workload.
```

---

## Summary

The SOC dashboard demonstrates the final operational workflow of the project:

```text
Sysmon Event
    ↓
ML ATT&CK Prediction
    ↓
LLM Explanation
    ↓
SOC Analyst Dashboard
```

It is intended to show how the trained ATT&CK classifier can be integrated into a practical SOC triage interface.
