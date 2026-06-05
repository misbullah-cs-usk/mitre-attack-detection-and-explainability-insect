# Explainable Sequence-Based MITRE ATT&CK Technique Detection from Endpoint Telemetry Using AI and Large Language Models

## Project Overview

This project develops an AI-assisted cybersecurity system for predicting MITRE ATT&CK techniques from Windows/Sysmon logs. The system uses Splunk Attack Data as the main dataset and focuses on automatic ATT&CK technique classification, hierarchical parent/sub-technique prediction, sequence-based behavior learning, Transformer-based classification, and LLM-based SOC explanation.

The main goal is to support SOC analysts by reducing manual ATT&CK mapping effort and providing explainable alert triage. Instead of only predicting a label, the system also generates analyst-friendly explanations, recommended investigation steps, false-positive checks, and Splunk search ideas.

The project contains several experiment stages:

1. **Event-Level ATT&CK Classification**
   Each Sysmon event is treated as one independent sample. A TF-IDF + SGD classifier and Transformer model are trained to predict ATT&CK techniques.

2. **Hierarchical ATT&CK Classification**
   Two models are trained:

   * Parent-technique model, for example `T1059`
   * Sub-technique model, for example `T1059.001`

   If the sub-technique confidence is low or inconsistent with the parent prediction, the system falls back to the safer parent-technique prediction.

3. **Sequence-Based Classification**
   Multiple Sysmon events are grouped into behavioral sequences to capture temporal attack context.

4. **Sliding-Window Sequence Classification**
   Sliding-window sequences are created using a fixed window size and stride. This improves the sequence dataset size and provides better temporal context for classical ML and Transformer models.

5. **Transformer-Based ATT&CK Prediction**
   Transformer models such as MiniLM, DistilBERT, or DistilRoBERTa are fine-tuned for ATT&CK technique classification.

6. **LLM-Based SOC Explanation**
   A local LLM through Ollama, such as `qwen2.5:3b-instruct`, is used to explain the ML prediction. The LLM does not replace the classifier; it acts as an explanation layer.

7. **SOC Dashboard Demo**
   A FastAPI backend and JavaScript frontend are provided to demonstrate the complete workflow:

   ```text
   Sysmon Event
        ↓
   Feature Normalization
        ↓
   Hierarchical ML Classifier
        ↓
   ATT&CK Prediction
        ↓
   Qwen LLM Explanation
        ↓
   SOC Dashboard
   ```

---

## Project Structure

```text
project/
├── data/
│   ├── sysmon_events_labeled.csv
│   ├── sysmon_events_text.csv
│   ├── sysmon_events_split.csv
│   ├── sysmon_sequences_split.csv
│   ├── sysmon_sequences_window_size10_split.csv
│   └── llm_sft_mitre_explanation.json
│
├── models/
│   ├── tfidf_sgd_parent.joblib
│   ├── tfidf_sgd_subtechnique.joblib
│   ├── tfidf_sgd_sequence_parent.joblib
│   ├── tfidf_sgd_sequence_subtechnique.joblib
│   ├── tfidf_sgd_sequence_window_parent.joblib
│   └── tfidf_sgd_sequence_window_subtechnique.joblib
│
├── reports/
│   ├── hierarchical_classical_ml_test_predictions.csv
│   ├── sequence_classical_ml_test_predictions.csv
│   ├── sequence_window_classical_ml_test_predictions.csv
│   ├── event_transformer_subtechnique_report.txt
│   ├── sequence_transformer_subtechnique_report.txt
│   ├── sequence_window_transformer_subtechnique_report.txt
│   └── ml_plus_llm_explanation_example.json
│
├── soc_dashboard/
│   ├── app.py
│   ├── ml_predict_then_llm_explain.py
│   └── static/
│       ├── index.html
│       ├── app.js
│       └── style.css
│
├── 01_build_dataset.py
├── 02_prepare_features.py
├── 03_split_dataset.py
├── 04_train_event_flat_classical_ml.py
├── 05_train_event_hierarchical_classical_ml.py
├── 06_predict_event_hierarchical.py
├── 07_build_sequence_dataset.py
├── 08_build_sequence_window_dataset.py
├── 09_train_sequence_hierarchical_classical_ml.py
├── 10_predict_sequence_hierarchical.py
├── 11_train_sequence_window_hierarchical_classical_ml.py
├── 12_train_event_transformer.py
├── 13_train_sequence_transformer.py
├── 14_train_sequence_window_transformer.py
├── 15_llm_detect_single_log.py
├── 16_llm_detect_dataset.py
├── 17_ml_predict_then_llm_explain.py
└── 18_create_llm_sft_dataset.py
```

---

## System Requirements

### Hardware

Recommended:

```text
CPU: 8 cores or higher
RAM: 32 GB or higher
GPU: NVIDIA GPU with CUDA support recommended for Transformer training
Disk: 50 GB or higher
```

For classical ML experiments, CPU training is sufficient.

For Transformer experiments, GPU is strongly recommended.

For the SOC dashboard demo, CPU is enough if the ML models are already trained. However, LLM explanation speed depends on the Ollama model and hardware.

---

### Software

Tested environment:

```text
OS: Linux
Python: 3.10+
CUDA: Optional, required only for GPU Transformer training
Ollama: Required for local LLM explanation
```

Required Python packages:

```bash
pip install pandas numpy scikit-learn joblib tqdm
pip install torch transformers datasets accelerate evaluate
pip install fastapi uvicorn requests
```

Optional packages:

```bash
pip install matplotlib seaborn
```

---

## Ollama Requirement

The SOC explanation module uses Ollama.

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

## Dataset Preparation

The project expects Splunk Attack Data to be available locally.

Example expected raw dataset path:

```text
/home/alim/PhD-Experiments/Alim/CyberSecurity/data/raw/attack_data/datasets/attack_techniques
```

The raw dataset should contain MITRE ATT&CK technique folders such as:

```text
T1059.001/
T1003.001/
T1547.001/
T1562.001/
```

Each folder contains Sysmon log files.

---

## How to Run

### 1. Build Event Dataset

```bash
python 01_build_dataset.py
python 02_prepare_features.py
python 03_split_dataset.py
```

These scripts perform:

```text
Raw Sysmon Logs
    ↓
Labeled Event Dataset
    ↓
Normalized Text Features
    ↓
Train / Validation / Test Split
```

Outputs:

```text
data/sysmon_events_labeled.csv
data/sysmon_events_text.csv
data/sysmon_events_split.csv
```

---

### 2. Train Event-Level Classical ML Models

```bash
python 04_train_event_flat_classical_ml.py
python 05_train_event_hierarchical_classical_ml.py
python 06_predict_event_hierarchical.py
```

Outputs:

```text
models/tfidf_sgd_technique_fast.joblib
models/tfidf_sgd_parent.joblib
models/tfidf_sgd_subtechnique.joblib
reports/hierarchical_classical_ml_test_predictions.csv
```

The hierarchical model predicts:

```text
Parent Technique: T1059
Sub-Technique: T1059.001
```

---

### 3. Build Sequence Datasets

```bash
python 07_build_sequence_dataset.py
python 08_build_sequence_window_dataset.py
```

Outputs:

```text
data/sysmon_sequences_split.csv
data/sysmon_sequences_window_size10_split.csv
```

The first sequence dataset groups events by source file.

The sliding-window sequence dataset uses:

```text
Window size = 10 events
Stride = 5 events
Minimum sequence length = 3 events
```

---

### 4. Train Sequence-Level Classical ML Models

```bash
python 09_train_sequence_hierarchical_classical_ml.py
python 10_predict_sequence_hierarchical.py
python 11_train_sequence_window_hierarchical_classical_ml.py
```

Outputs:

```text
models/tfidf_sgd_sequence_parent.joblib
models/tfidf_sgd_sequence_subtechnique.joblib
models/tfidf_sgd_sequence_window_parent.joblib
models/tfidf_sgd_sequence_window_subtechnique.joblib
reports/sequence_classical_ml_test_predictions.csv
reports/sequence_window_classical_ml_test_predictions.csv
```

---

### 5. Train Transformer Models

```bash
python 12_train_event_transformer.py
python 13_train_sequence_transformer.py
python 14_train_sequence_window_transformer.py
```

Outputs:

```text
models/event_transformer_subtechnique/
models/sequence_transformer_subtechnique/
models/sequence_window_transformer_subtechnique/
reports/event_transformer_subtechnique_report.txt
reports/sequence_transformer_subtechnique_report.txt
reports/sequence_window_transformer_subtechnique_report.txt
```

Transformer models are trained for sub-technique classification.

---

### 6. Run LLM Direct Detection Experiments

```bash
python 15_llm_detect_single_log.py
python 16_llm_detect_dataset.py
```

These scripts test whether a local LLM can directly classify Sysmon logs as:

```text
benign
suspicious
malicious
```

and suggest MITRE ATT&CK labels.

Output:

```text
reports/llm_detector_event_sample.csv
```

---

### 7. Run ML + LLM Explainability

```bash
python 17_ml_predict_then_llm_explain.py
```

This script performs:

```text
Sysmon Event
    ↓
ML Hierarchical Prediction
    ↓
Top-k ATT&CK Candidates
    ↓
Qwen LLM Explanation
    ↓
SOC-Friendly JSON Output
```

Output:

```text
reports/ml_plus_llm_explanation_example.json
```

---

### 8. Create LLM SFT Dataset

```bash
python 18_create_llm_sft_dataset.py
```

This creates supervised fine-tuning data for LLM-based SOC explanation.

Output:

```text
data/llm_sft_mitre_explanation.json
```

The generated SFT data follows an instruction-input-output format and can be used with LLaMA-Factory.

---

## Running the SOC Dashboard

The SOC dashboard provides an interactive demo interface.

### 1. Make sure models exist

Required files:

```text
models/tfidf_sgd_parent.joblib
models/tfidf_sgd_subtechnique.joblib
```

If they do not exist, run:

```bash
python 05_train_event_hierarchical_classical_ml.py
```

---

### 2. Start Ollama

```bash
ollama serve
```

In another terminal, check the model:

```bash
ollama list
```

Expected:

```text
qwen2.5:3b-instruct
```

---

### 3. Run the dashboard

From the project root:

```bash
cd soc_dashboard
python3 app.py
```

Open:

```text
http://localhost:8000
```

For a remote server:

```text
http://<server-ip>:8000
```

---

## SOC Dashboard Features

The dashboard supports:

```text
Built-in demo alerts
Sysmon event input
ATT&CK parent-technique prediction
ATT&CK sub-technique prediction
Confidence score
Top-k ATT&CK candidates
Technique name display
LLM-generated explanation
Triage priority
Recommended investigation steps
False-positive checks
Splunk search ideas
```

---

## Example Dashboard Workflow

```text
1. Select a demo alert
2. Click Load Example
3. Click Analyze Alert
4. View ATT&CK prediction
5. Review top-k candidate techniques
6. Read LLM explanation
7. Use suggested Splunk searches for investigation
```

---

## Important Notes

This project currently focuses on **ATT&CK technique classification**, not full benign-versus-malicious detection.

The current assumption is:

```text
Input log is already suspicious or malicious
```

Therefore, the model predicts:

```text
Which ATT&CK technique does this suspicious behavior belong to?
```

A full production SOC pipeline should include an earlier detection stage:

```text
Raw Logs
    ↓
Benign vs Malicious Detection
    ↓
ATT&CK Technique Classification
    ↓
LLM Explanation
    ↓
SOC Dashboard
```

Adding benign data is planned as future work.

---

## Main Outputs

| Output                                                | Description                                 |
| ----------------------------------------------------- | ------------------------------------------- |
| `sysmon_events_text.csv`                              | Event-level normalized text dataset         |
| `sysmon_events_split.csv`                             | Fixed train/validation/test event dataset   |
| `sysmon_sequences_split.csv`                          | Source-file grouped sequence dataset        |
| `sysmon_sequences_window_size10_split.csv`            | Sliding-window sequence dataset             |
| `tfidf_sgd_parent.joblib`                             | Event-level parent-technique classifier     |
| `tfidf_sgd_subtechnique.joblib`                       | Event-level sub-technique classifier        |
| `event_transformer_subtechnique_report.txt`           | Event Transformer result                    |
| `sequence_window_transformer_subtechnique_report.txt` | Sliding-window Transformer result           |
| `ml_plus_llm_explanation_example.json`                | ML + LLM SOC explanation example            |
| `llm_sft_mitre_explanation.json`                      | SFT dataset for LLM explanation fine-tuning |

---

## Summary

This project demonstrates a complete AI-assisted SOC workflow for MITRE ATT&CK prediction:

```text
Splunk Attack Data
    ↓
Sysmon Feature Engineering
    ↓
Classical ML and Transformer Models
    ↓
Hierarchical ATT&CK Prediction
    ↓
Local LLM Explanation
    ↓
SOC Dashboard Demo
```

The system is designed to support faster, more consistent, and more explainable SOC triage.
