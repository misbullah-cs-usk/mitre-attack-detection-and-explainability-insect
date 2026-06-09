# Explainable Sequence-Based MITRE ATT&CK Technique Detection from Endpoint Telemetry Using AI and Large Language Models

## Course: Cybersecurity and AI-based Analytics 

## Team Name: Insect
### Team Member: 
- Danis Putra Perdana D11415806
- Alim Misbullah D11415803
- Laina Farsiah D11415802
- Puspa Ira Dewi Candra Wulan D11415807
- Aurelio Naufal Effendy M11415802
- 陳增勇 B11007106

## Project Overview

This project develops an AI-assisted cybersecurity system for predicting MITRE ATT&CK techniques from Windows/Sysmon logs. The main dataset is Splunk Attack Data, which contains attack execution logs organized by MITRE ATT&CK technique labels.

The project focuses on **ATT&CK technique attribution**, not full benign-versus-malicious detection. The main assumption is that the input log is already suspicious or malicious, and the model predicts which ATT&CK technique or sub-technique best describes the behavior.

The experiment includes:

* Event-level ATT&CK classification
* Hierarchical parent-technique and sub-technique classification
* Sequence-based learning
* Sliding-window sequence learning
* Transformer-based ATT&CK prediction
* LLM-based SOC explanation data preparation

---

## Research Objectives

### Detection Objectives

* Detect malicious behavior patterns from Windows/Sysmon logs.
* Predict MITRE ATT&CK techniques automatically.
* Support both parent-technique and sub-technique classification.

### AI Objectives

* Compare classical ML and Transformer-based models.
* Compare event-level and sequence-level feature representations.
* Evaluate whether sliding-window sequence construction improves temporal behavior learning.

### Explainability Objectives

* Prepare structured data for LLM-based SOC explanations.
* Generate SFT data for future fine-tuning of a local security assistant model.

---

## Dataset

The project uses Splunk Attack Data.

Expected raw dataset path:

```text
/home/alim/PhD-Experiments/Alim/CyberSecurity/data/raw/attack_data/datasets/attack_techniques
```

Example ATT&CK technique folders:

```text
T1059.001/
T1003.001/
T1547.001/
T1562.001/
```

Each folder contains Sysmon log files related to a specific ATT&CK technique.

---

## Dataset Representation

This project creates three main dataset representations.

### 1. Event-Level Dataset

Each Sysmon event is treated as one independent sample.

```text
One Sysmon Event → ATT&CK Technique
```

Example:

```text
EventID=1
Image=powershell.exe
CommandLine=powershell.exe -enc ...
ParentImage=cmd.exe
Label=T1059.001
```

### 2. Sequence V1 Dataset

Events are grouped by source file and technique.

```text
Event 1 + Event 2 + ... + Event N → ATT&CK Technique
```

This captures full attack context, but produces a small number of sequence samples.

### 3. Sliding-Window Sequence Dataset

Events are grouped using a sliding window.

```text
Window size = 10 events
Stride = 5 events
```

Example:

```text
Window 1: Event 1–10
Window 2: Event 6–15
Window 3: Event 11–20
```

This representation provides a better balance between temporal context and dataset size.

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

Classical ML experiments can run on CPU.

Transformer experiments are faster with GPU.

### Software

Recommended environment:

```text
OS: Linux
Python: 3.10+
CUDA: Optional, required only for GPU-based Transformer training
```

Install required packages:

```bash
pip install pandas numpy scikit-learn joblib tqdm
pip install torch transformers datasets accelerate evaluate
```

Optional:

```bash
pip install matplotlib seaborn
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

## Source Code Order and Purpose

| Order | File Name                                               | Purpose                                                                                |
| ----: | ------------------------------------------------------- | -------------------------------------------------------------------------------------- |
|     1 | `01_build_dataset.py`                                   | Parse raw Splunk Attack Data Sysmon logs into labeled event records.                   |
|     2 | `02_prepare_features.py`                                | Normalize Sysmon fields and generate event-level text features.                        |
|     3 | `03_split_dataset.py`                                   | Create fixed train, validation, and test splits with balanced technique labels.        |
|     4 | `04_train_event_flat_classical_ml.py`                   | Train a flat event-level TF-IDF + SGD model for direct ATT&CK technique prediction.    |
|     5 | `05_train_event_hierarchical_classical_ml.py`           | Train event-level parent-technique and sub-technique hierarchical classical ML models. |
|     6 | `06_predict_event_hierarchical.py`                      | Run sample inference using the event-level hierarchical ML models.                     |
|     7 | `07_build_sequence_dataset.py`                          | Build the first sequence dataset by grouping events by source file.                    |
|     8 | `08_build_sequence_window_dataset.py`                   | Build the improved sliding-window sequence dataset.                                    |
|     9 | `09_train_sequence_hierarchical_classical_ml.py`        | Train hierarchical classical ML models on the source-file sequence dataset.            |
|    10 | `10_predict_sequence_hierarchical.py`                   | Run sample inference using the sequence-level hierarchical ML models.                  |
|    11 | `11_train_sequence_window_hierarchical_classical_ml.py` | Train hierarchical classical ML models on the sliding-window sequence dataset.         |
|    12 | `12_train_event_transformer.py`                         | Train an event-level Transformer model for ATT&CK sub-technique prediction.            |
|    13 | `13_train_sequence_transformer.py`                      | Train a Transformer model on the source-file sequence dataset.                         |
|    14 | `14_train_sequence_window_transformer.py`               | Train a Transformer model on the sliding-window sequence dataset.                      |
|    15 | `15_llm_detect_single_log.py`                           | Test the local LLM as a direct detector on one Sysmon log.                             |
|    16 | `16_llm_detect_dataset.py`                              | Test the local LLM as a direct detector on sampled test events.                        |
|    17 | `17_ml_predict_then_llm_explain.py`                     | Combine ML-based ATT&CK prediction with LLM-generated SOC explanation.                 |
|    18 | `18_create_llm_sft_dataset.py`                          | Generate supervised fine-tuning data for LLM-based SOC explanations.                   |

---

## How to Run

### 1. Build Event Dataset

```bash
python 01_build_dataset.py
python 02_prepare_features.py
python 03_split_dataset.py
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

The hierarchical model trains two classifiers:

```text
Parent Technique Model: T1059
Sub-Technique Model: T1059.001
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

---

### 6. Run LLM Direct Detection Experiments

```bash
python 15_llm_detect_single_log.py
python 16_llm_detect_dataset.py
```

Output:

```text
reports/llm_detector_event_sample.csv
```

These scripts test whether a local LLM can directly classify Sysmon logs as:

```text
benign
suspicious
malicious
```

and suggest possible ATT&CK labels.

---

### 7. Run ML + LLM Explainability

```bash
python 17_ml_predict_then_llm_explain.py
```

Output:

```text
reports/ml_plus_llm_explanation_example.json
```

This script performs:

```text
Sysmon Event
    ↓
ML Hierarchical Prediction
    ↓
Top-k ATT&CK Candidates
    ↓
LLM Explanation
    ↓
SOC-Friendly JSON Output
```

---

### 8. Create LLM SFT Dataset

```bash
python 18_create_llm_sft_dataset.py
```

Output:

```text
data/llm_sft_mitre_explanation.json
```

This file can be used for future supervised fine-tuning with LLaMA-Factory.

---

## Main Experimental Outputs

| Output                                                        | Description                                  |
| ------------------------------------------------------------- | -------------------------------------------- |
| `data/sysmon_events_text.csv`                                 | Event-level normalized text dataset          |
| `data/sysmon_events_split.csv`                                | Fixed train/validation/test event dataset    |
| `data/sysmon_sequences_split.csv`                             | Source-file grouped sequence dataset         |
| `data/sysmon_sequences_window_size10_split.csv`               | Sliding-window sequence dataset              |
| `models/tfidf_sgd_parent.joblib`                              | Event-level parent-technique classifier      |
| `models/tfidf_sgd_subtechnique.joblib`                        | Event-level sub-technique classifier         |
| `models/tfidf_sgd_sequence_window_parent.joblib`              | Sliding-window parent-technique classifier   |
| `models/tfidf_sgd_sequence_window_subtechnique.joblib`        | Sliding-window sub-technique classifier      |
| `reports/event_transformer_subtechnique_report.txt`           | Event Transformer evaluation report          |
| `reports/sequence_window_transformer_subtechnique_report.txt` | Sliding-window Transformer evaluation report |
| `reports/ml_plus_llm_explanation_example.json`                | ML + LLM explanation example                 |
| `data/llm_sft_mitre_explanation.json`                         | SFT dataset for LLM explanation fine-tuning  |

---

## Important Note About Benign Class

This project currently focuses on **ATT&CK technique classification**, not full benign-versus-malicious detection.

The current assumption is:

```text
Input logs are already suspicious or malicious.
```

Therefore, the model answers:

```text
Which ATT&CK technique does this suspicious behavior belong to?
```

A full production SOC pipeline should include an earlier benign-vs-malicious detection stage:

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

Adding benign samples is planned as future work.

---

## Summary

This experiment demonstrates a complete ATT&CK prediction workflow:

```text
Splunk Attack Data
    ↓
Sysmon Feature Engineering
    ↓
Classical ML and Transformer Models
    ↓
Hierarchical ATT&CK Prediction
    ↓
LLM Explanation Data Preparation
```

The system is designed to support faster and more consistent ATT&CK mapping for SOC triage.

