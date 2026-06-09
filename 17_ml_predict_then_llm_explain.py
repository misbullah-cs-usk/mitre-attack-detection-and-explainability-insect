import json
import re
import requests
import joblib
import numpy as np
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:7b-instruct"

PARENT_MODEL_PATH = "models/tfidf_sgd_parent.joblib"
SUB_MODEL_PATH = "models/tfidf_sgd_subtechnique.joblib"

# Use sequence models instead if needed:
# PARENT_MODEL_PATH = "models/tfidf_sgd_sequence_window_parent.joblib"
# SUB_MODEL_PATH = "models/tfidf_sgd_sequence_window_subtechnique.joblib"

SUBTECHNIQUE_THRESHOLD = 0.60
LOW_CONFIDENCE_THRESHOLD = 0.30
MEDIUM_CONFIDENCE_THRESHOLD = 0.60


# ============================================================
# Load ML models
# ============================================================

print("[1/5] Loading ML models...")

parent_model = joblib.load(PARENT_MODEL_PATH)
sub_model = joblib.load(SUB_MODEL_PATH)


# ============================================================
# Text normalization
# Must be consistent with training feature preparation
# ============================================================

TEXT_FIELDS = [
    "EventID",
    "Image",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "User",
    "Computer",
    "TargetFilename",
    "TargetObject",
    "Details",
    "DestinationIp",
    "DestinationPort",
    "SourceIp",
    "SourcePort",
    "QueryName",
    "CurrentDirectory",
]


def normalize_text(s: str) -> str:
    s = str(s).lower()
    s = re.sub(r"[a-z]:\\users\\[^\\\s]+", r"c:\\users\\<user>", s)
    s = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<ip>", s)
    s = re.sub(r"\b[0-9a-f]{32,64}\b", "<hash>", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def event_dict_to_text(event: dict) -> str:
    parts = []

    for field in TEXT_FIELDS:
        value = event.get(field, "")
        value = normalize_text(value)

        if value:
            parts.append(f"{field}={value}")

    return " ".join(parts)


def get_parent(label: str) -> str:
    return str(label).split(".")[0]


# ============================================================
# ML prediction functions
# ============================================================

def topk(model, text: str, k: int = 5):
    proba = model.predict_proba([text])[0]
    classes = model.classes_

    idx = np.argsort(proba)[::-1][:k]

    return [
        {
            "label": str(classes[i]),
            "confidence": round(float(proba[i]), 6)
        }
        for i in idx
    ]


def confidence_level(confidence: float) -> str:
    if confidence < LOW_CONFIDENCE_THRESHOLD:
        return "low"
    elif confidence < MEDIUM_CONFIDENCE_THRESHOLD:
        return "medium"
    else:
        return "high"


def predict_hierarchical(text: str):
    parent_top3 = topk(parent_model, text, k=3)
    sub_top5 = topk(sub_model, text, k=5)

    best_parent = parent_top3[0]
    best_sub = sub_top5[0]

    parent_label = best_parent["label"]
    sub_label = best_sub["label"]

    parent_conf = best_parent["confidence"]
    sub_conf = best_sub["confidence"]

    # Conservative decision logic
    if sub_conf >= SUBTECHNIQUE_THRESHOLD and get_parent(sub_label) == parent_label:
        final_label = sub_label
        final_level = "sub-technique"
        final_confidence = sub_conf
        decision_reason = (
            "Sub-technique prediction was accepted because its confidence "
            "passed the threshold and its parent matched the parent model."
        )
    else:
        final_label = parent_label
        final_level = "parent-technique"
        final_confidence = parent_conf
        decision_reason = (
            "Sub-technique prediction was rejected because confidence was too low "
            "or its parent did not match the parent model. The system returned "
            "the safer parent-technique prediction."
        )

    return {
        "final_label": final_label,
        "final_level": final_level,
        "confidence": final_confidence,
        "confidence_level": confidence_level(final_confidence),
        "decision_reason": decision_reason,
        "parent_top3": parent_top3,
        "subtechnique_top5": sub_top5
    }


# ============================================================
# Ollama LLM explanation
# ============================================================

def call_ollama(prompt: str):
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_ctx": 4096
        }
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=180
    )

    response.raise_for_status()
    return response.json()["response"]


def extract_json(raw: str):
    """
    Some local LLMs may wrap JSON in markdown.
    This tries to recover valid JSON safely.
    """
    raw = raw.strip()

    try:
        return json.loads(raw)
    except Exception:
        pass

    match = re.search(r"\{.*\}", raw, flags=re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except Exception:
            pass

    return {
        "summary": "LLM did not return valid JSON.",
        "attack_interpretation": raw,
        "why_prediction_makes_sense": [],
        "confidence_interpretation": "Unable to parse structured explanation.",
        "triage_priority": "unknown",
        "recommended_triage_steps": [],
        "false_positive_checks": [],
        "splunk_search_ideas": []
    }


def build_explanation_prompt(event_text: str, ml_prediction: dict):
    alert = {
        "log": event_text,
        "ml_prediction": ml_prediction
    }

    prompt = f"""
You are a SOC analyst assistant.

The ML model has already predicted a MITRE ATT&CK label.
Your task is to explain the alert, not to replace the ML model.

Important rules:
- Do not invent facts that are not present in the log.
- If evidence is weak, say so clearly.
- If confidence is low, recommend analyst review.
- If the final prediction is parent-technique only, explain why sub-technique was not accepted.
- Keep the explanation practical for SOC triage.
- Return ONLY valid JSON.
- Do not use markdown.

Return this JSON schema:

{{
  "summary": "...",
  "attack_interpretation": "...",
  "why_prediction_makes_sense": ["...", "..."],
  "confidence_interpretation": "...",
  "triage_priority": "low|medium|high",
  "recommended_triage_steps": ["...", "..."],
  "false_positive_checks": ["...", "..."],
  "splunk_search_ideas": ["...", "..."]
}}

Alert:
{json.dumps(alert, indent=2)}
"""

    return prompt


def explain_with_llm(event_text: str, ml_prediction: dict):
    prompt = build_explanation_prompt(event_text, ml_prediction)
    raw_response = call_ollama(prompt)
    parsed = extract_json(raw_response)

    return {
        "raw_llm_response": raw_response,
        "llm_explanation": parsed
    }


# ============================================================
# Main demo
# ============================================================

if __name__ == "__main__":

    print("[2/5] Preparing input log...")

    event = {
        "EventID": "1",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ParentCommandLine": "cmd.exe /c powershell.exe -enc SQBFAFgA...",
        "User": r"corp\alice",
        "Computer": "win10-01",
        "TargetFilename": "",
        "TargetObject": "",
        "Details": "",
        "DestinationIp": "",
        "DestinationPort": "",
        "SourceIp": "",
        "SourcePort": "",
        "QueryName": "",
        "CurrentDirectory": r"C:\Users\alice\Downloads"
    }

    event_text = event_dict_to_text(event)

    print("\nNormalized event text:")
    print(event_text)

    print("\n[3/5] Running ML hierarchical prediction...")
    ml_prediction = predict_hierarchical(event_text)

    print("\nML prediction:")
    print(json.dumps(ml_prediction, indent=2))

    print("\n[4/5] Sending ML prediction to Ollama for explanation...")
    llm_result = explain_with_llm(event_text, ml_prediction)

    print("\n[5/5] Final SOC alert explanation:")

    final_output = {
        "event_text": event_text,
        "ml_prediction": ml_prediction,
        "llm_explanation": llm_result["llm_explanation"]
    }

    print(json.dumps(final_output, indent=2))

    Path("reports").mkdir(exist_ok=True)

    with open("reports/ml_plus_llm_explanation_example.json", "w") as f:
        json.dump(final_output, f, indent=2)

    print("\nSaved:")
    print("reports/ml_plus_llm_explanation_example.json")
