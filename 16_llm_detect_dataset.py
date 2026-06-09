import requests
import json
import time
from pathlib import Path
import pandas as pd
from tqdm import tqdm

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:7b-instruct"

INPUT_FILE = "data/sysmon_events_split.csv"
OUTPUT_FILE = "reports/llm_detector_event_sample.csv"

SPLIT = "test"
SAMPLE_SIZE = 100

Path("reports").mkdir(exist_ok=True)


def call_ollama(log_text):
    prompt = f"""
You are a SOC analyst.

Analyze the Windows/Sysmon log below.

Return ONLY valid JSON with this schema:

{{
  "verdict": "benign|suspicious|malicious",
  "confidence": 0.0,
  "parent_technique": "Txxxx or null",
  "sub_technique": "Txxxx.xxx or null",
  "reason": "...",
  "triage_steps": ["...", "..."],
  "possible_false_positive": "..."
}}

Rules:
- If the log shows normal administrative or system activity, use "benign".
- If the log has weak attack indicators, use "suspicious".
- If the log strongly matches ATT&CK behavior, use "malicious".
- Do not invent evidence that is not in the log.
- Keep the reason short.

Log:
{log_text}
"""

    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_ctx": 4096
        }
    }

    r = requests.post(OLLAMA_URL, json=payload, timeout=120)
    r.raise_for_status()
    return r.json()["response"]


def safe_parse_json(raw):
    try:
        return json.loads(raw)
    except Exception:
        return {
            "verdict": "parse_error",
            "confidence": None,
            "parent_technique": None,
            "sub_technique": None,
            "reason": raw,
            "triage_steps": [],
            "possible_false_positive": None
        }


df = pd.read_csv(INPUT_FILE, dtype=str, low_memory=False).fillna("")
df = df[df["split"] == SPLIT].copy()

sample = df.sample(min(SAMPLE_SIZE, len(df)), random_state=42)

rows = []

for _, row in tqdm(sample.iterrows(), total=len(sample)):
    log_text = row["text"]

    try:
        raw = call_ollama(log_text)
        parsed = safe_parse_json(raw)
    except Exception as e:
        raw = str(e)
        parsed = {
            "verdict": "error",
            "confidence": None,
            "parent_technique": None,
            "sub_technique": None,
            "reason": str(e),
            "triage_steps": [],
            "possible_false_positive": None
        }

    rows.append({
        "true_technique": row["technique"],
        "true_parent": row["technique"].split(".")[0],
        "llm_verdict": parsed.get("verdict"),
        "llm_confidence": parsed.get("confidence"),
        "llm_parent": parsed.get("parent_technique"),
        "llm_subtechnique": parsed.get("sub_technique"),
        "llm_reason": parsed.get("reason"),
        "llm_triage_steps": json.dumps(parsed.get("triage_steps", [])),
        "llm_false_positive": parsed.get("possible_false_positive"),
        "raw_response": raw,
        "text": log_text
    })

    time.sleep(0.2)

out = pd.DataFrame(rows)
out.to_csv(OUTPUT_FILE, index=False)

print("Saved:", OUTPUT_FILE)

print("\nVerdict counts:")
print(out["llm_verdict"].value_counts())

print("\nParent match rate:")
out["parent_correct"] = out["true_parent"] == out["llm_parent"]
print(out["parent_correct"].mean())

print("\nSub-technique match rate:")
out["sub_correct"] = out["true_technique"] == out["llm_subtechnique"]
print(out["sub_correct"].mean())
