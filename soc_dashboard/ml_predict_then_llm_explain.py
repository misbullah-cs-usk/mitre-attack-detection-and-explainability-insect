import json
import re
from pathlib import Path

import joblib
import numpy as np
import requests


# =========================
# Config
# =========================

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:3b-instruct"

PARENT_MODEL_PATH = "models/tfidf_sgd_parent.joblib"
SUB_MODEL_PATH = "models/tfidf_sgd_subtechnique.joblib"

SUBTECHNIQUE_THRESHOLD = 0.60


# =========================
# Load models once
# =========================

parent_model = joblib.load(PARENT_MODEL_PATH)
sub_model = joblib.load(SUB_MODEL_PATH)


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


# =========================
# Feature preparation
# =========================

def normalize_text(value: str) -> str:
    value = str(value).lower()
    value = re.sub(r"[a-z]:\\users\\[^\\\s]+", r"c:\\users\\<user>", value)
    value = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<ip>", value)
    value = re.sub(r"\b[0-9a-f]{32,64}\b", "<hash>", value)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


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


# =========================
# ML prediction
# =========================

def topk(model, text: str, k: int = 5):
    proba = model.predict_proba([text])[0]
    classes = model.classes_

    idx = np.argsort(proba)[::-1][:k]

    return [
        {
            "label": str(classes[i]),
            "confidence": float(proba[i])
        }
        for i in idx
    ]


def confidence_level(conf: float) -> str:
    if conf < 0.30:
        return "low"
    if conf < 0.60:
        return "medium"
    return "high"


def predict_hierarchical(event_text: str):
    parent_top3 = topk(parent_model, event_text, k=3)
    sub_top5 = topk(sub_model, event_text, k=5)

    best_parent = parent_top3[0]
    best_sub = sub_top5[0]

    parent_label = best_parent["label"]
    sub_label = best_sub["label"]

    parent_conf = best_parent["confidence"]
    sub_conf = best_sub["confidence"]

    if sub_conf >= SUBTECHNIQUE_THRESHOLD and get_parent(sub_label) == parent_label:
        final_label = sub_label
        final_level = "sub-technique"
        final_confidence = sub_conf
        decision_reason = (
            "Sub-technique prediction was accepted because its confidence "
            "passed the threshold and its parent matched the parent prediction."
        )
    else:
        final_label = parent_label
        final_level = "parent-technique"
        final_confidence = parent_conf
        decision_reason = (
            "Sub-technique prediction was not accepted because confidence was too low "
            "or its parent did not match the parent prediction. The system returned "
            "the safer parent-technique result."
        )

    return {
        "final_label": final_label,
        "final_level": final_level,
        "confidence": final_confidence,
        "confidence_level": confidence_level(final_confidence),
        "decision_reason": decision_reason,
        "parent_top3": parent_top3,
        "subtechnique_top5": sub_top5,
    }


# =========================
# LLM explanation
# =========================

def build_explanation_prompt(event_text: str, ml_prediction: dict) -> str:
    alert = {
        "log": event_text,
        "ml_prediction": ml_prediction,
    }

    return f"""
You are a SOC analyst assistant.

The ML model already predicted a MITRE ATT&CK label.
Your job is to explain the alert for an analyst.

Rules:
- Do not override the ML prediction unless there is clear contradiction.
- Do not invent evidence not present in the log.
- If confidence is low, say analyst review is required.
- Return ONLY valid JSON.
- Do not use markdown.

Return exactly this JSON schema:

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


def call_ollama(prompt: str) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_ctx": 4096,
        },
    }

    response = requests.post(OLLAMA_URL, json=payload, timeout=180)
    response.raise_for_status()

    return response.json().get("response", "")


def extract_json(raw: str) -> dict:
    raw = raw.strip()

    try:
        return json.loads(raw)
    except Exception:
        pass

    raw = raw.replace("```json", "").replace("```", "").strip()

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
        "summary": "LLM response could not be parsed as valid JSON.",
        "attack_interpretation": raw,
        "why_prediction_makes_sense": [],
        "confidence_interpretation": "Parsing failed. Review raw LLM output.",
        "triage_priority": "medium",
        "recommended_triage_steps": [
            "Review the original Sysmon event manually.",
            "Check surrounding events from the same host, user, and process tree.",
        ],
        "false_positive_checks": [
            "Verify whether the command or process is expected in this environment."
        ],
        "splunk_search_ideas": [
            "index=* Computer=<host>",
            "index=* Image=<process> OR CommandLine=<command>",
        ],
    }


def explain_with_llm(event_text: str, ml_prediction: dict) -> dict:
    prompt = build_explanation_prompt(event_text, ml_prediction)
    raw = call_ollama(prompt)
    parsed = extract_json(raw)

    return {
        "raw_llm_response": raw,
        "llm_explanation": parsed,
    }


# =========================
# Full pipeline
# =========================

def analyze_event(event: dict) -> dict:
    event_text = event_dict_to_text(event)
    ml_prediction = predict_hierarchical(event_text)
    llm_result = explain_with_llm(event_text, ml_prediction)

    return {
        "event_text": event_text,
        "ml_prediction": ml_prediction,
        "llm_explanation": llm_result["llm_explanation"],
        "raw_llm_response": llm_result["raw_llm_response"],
    }


# =========================
# Demo run
# =========================

if __name__ == "__main__":
    sample_event = {
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
        "CurrentDirectory": r"C:\Users\alice\Downloads",
    }

    result = analyze_event(sample_event)

    Path("reports").mkdir(exist_ok=True)

    with open("reports/ml_plus_llm_explanation_example.json", "w") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))
