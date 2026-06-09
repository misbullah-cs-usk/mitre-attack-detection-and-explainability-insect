import json
import pandas as pd
from pathlib import Path

INPUT_FILE = "reports/hierarchical_classical_ml_test_predictions.csv"
OUTPUT_FILE = "data/llm_sft_mitre_explanation.json"

SAMPLE_SIZE = 5000

Path("data").mkdir(exist_ok=True)

df = pd.read_csv(INPUT_FILE, dtype=str, low_memory=False).fillna("")

# Prefer correct ML predictions first for clean SFT
correct_df = df[df["technique_correct"] == "True"].copy()

if len(correct_df) < SAMPLE_SIZE:
    sample = correct_df
else:
    sample = correct_df.sample(SAMPLE_SIZE, random_state=42)

records = []

system_prompt = (
    "You are a SOC analyst assistant. "
    "You explain Windows/Sysmon alerts mapped to MITRE ATT&CK. "
    "Always return valid JSON only. Do not use markdown."
)

for _, row in sample.iterrows():
    true_technique = row["technique"]
    true_parent = row["parent_technique"]
    pred_technique = row["pred_technique"]
    pred_parent = row["pred_parent"]

    log_text = row["text"]

    instruction = """
Given a Windows/Sysmon log and an ML ATT&CK prediction, generate a structured SOC explanation.

Return ONLY valid JSON with this schema:
{
  "summary": "...",
  "verdict": "suspicious|malicious",
  "parent_technique": "Txxxx",
  "sub_technique": "Txxxx.xxx or null",
  "why_prediction_makes_sense": ["...", "..."],
  "triage_priority": "low|medium|high",
  "recommended_triage_steps": ["...", "..."],
  "false_positive_checks": ["...", "..."],
  "splunk_search_ideas": ["...", "..."]
}
"""

    input_obj = {
        "log": log_text,
        "ml_prediction": {
            "predicted_parent": pred_parent,
            "predicted_technique": pred_technique
        }
    }

    # Simple template output.
    # You can improve this manually later.
    output_obj = {
        "summary": f"The activity is mapped to MITRE ATT&CK {true_technique}.",
        "verdict": "malicious",
        "parent_technique": true_parent,
        "sub_technique": true_technique if "." in true_technique else None,
        "why_prediction_makes_sense": [
            "The log contains process, command, file, registry, or network evidence associated with the predicted ATT&CK behavior.",
            "The ML prediction is consistent with the labeled Splunk Attack Data technique."
        ],
        "triage_priority": "medium",
        "recommended_triage_steps": [
            "Review surrounding Sysmon events from the same host and user.",
            "Check the process tree, command line, parent process, and related network/file/registry activity.",
            "Compare the activity with known administrative behavior in the environment."
        ],
        "false_positive_checks": [
            "Verify whether the command or process is expected for this user or host.",
            "Check whether the activity was caused by legitimate administration, software update, or monitoring tools."
        ],
        "splunk_search_ideas": [
            f'index=* "{true_technique}"',
            "index=* EventID=* Computer=<host>",
            "index=* Image=<process> OR CommandLine=<command>"
        ]
    }

    records.append({
        "instruction": instruction.strip(),
        "input": json.dumps(input_obj, indent=2),
        "output": json.dumps(output_obj, indent=2),
        "system": system_prompt
    })

with open(OUTPUT_FILE, "w") as f:
    json.dump(records, f, indent=2)

print("Saved:", OUTPUT_FILE)
print("Records:", len(records))
