# mitre-attack-detection-and-explainability-insect
Implementation of MITRE ATT&amp;CK Detection and LLM Explainability - Cybersecurity and AI-based Analytics

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

## Exact Run Order

### 1. Build Event Dataset

```bash
python 01_build_dataset.py
python 02_prepare_features.py
python 03_split_dataset.py
```

### 2. Event-Level Classical ML

```bash
python 04_train_event_flat_classical_ml.py
python 05_train_event_hierarchical_classical_ml.py
python 06_predict_event_hierarchical.py
```

### 3. Build Sequence Datasets

```bash
python 07_build_sequence_dataset.py
python 08_build_sequence_window_dataset.py
```

### 4. Sequence-Level Classical ML

```bash
python 09_train_sequence_hierarchical_classical_ml.py
python 10_predict_sequence_hierarchical.py
python 11_train_sequence_window_hierarchical_classical_ml.py
```

### 5. Transformer Experiments

```bash
python 12_train_event_transformer.py
python 13_train_sequence_transformer.py
python 14_train_sequence_window_transformer.py
```

### 6. LLM Direct Detection Experiments

```bash
python 15_llm_detect_single_log.py
python 16_llm_detect_dataset.py
```

### 7. ML + LLM Explainability

```bash
python 17_ml_predict_then_llm_explain.py
```

### 8. Create LLM SFT Dataset

```bash
python 18_create_llm_sft_dataset.py
```
 
