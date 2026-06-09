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
OLLAMA_MODEL = "qwen2.5:3b-instruct"

PARENT_MODEL_PATH = "../models/tfidf_sgd_parent.joblib"
SUB_MODEL_PATH = "../models/tfidf_sgd_subtechnique.joblib"

# If you run uvicorn from project root, use this instead:
# PARENT_MODEL_PATH = "models/tfidf_sgd_parent.joblib"
# SUB_MODEL_PATH = "models/tfidf_sgd_subtechnique.joblib"

SUBTECHNIQUE_THRESHOLD = 0.60
LOW_CONFIDENCE_THRESHOLD = 0.30
MEDIUM_CONFIDENCE_THRESHOLD = 0.60


# ============================================================
# ATT&CK technique name helper
# ============================================================

ATTACK_NAMES = {
    "T1003": "OS Credential Dumping",
    "T1003.001": "LSASS Memory",
    "T1003.002": "Security Account Manager",
    "T1003.003": "NTDS",
    "T1016": "System Network Configuration Discovery",
    "T1018": "Remote System Discovery",
    "T1021": "Remote Services",
    "T1021.002": "SMB/Windows Admin Shares",
    "T1021.003": "Distributed Component Object Model",
    "T1021.006": "Windows Remote Management",
    "T1027": "Obfuscated Files or Information",
    "T1033": "System Owner/User Discovery",
    "T1036": "Masquerading",
    "T1036.003": "Rename System Utilities",
    "T1047": "Windows Management Instrumentation",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1048.003": "Exfiltration Over Unencrypted Non-C2 Protocol",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task",
    "T1055": "Process Injection",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.003": "Windows Command Shell",
    "T1059.005": "Visual Basic",
    "T1068": "Exploitation for Privilege Escalation",
    "T1069": "Permission Groups Discovery",
    "T1069.001": "Local Groups",
    "T1069.002": "Domain Groups",
    "T1070": "Indicator Removal",
    "T1070.001": "Clear Windows Event Logs",
    "T1070.005": "Network Share Connection Removal",
    "T1078": "Valid Accounts",
    "T1078.002": "Domain Accounts",
    "T1082": "System Information Discovery",
    "T1087": "Account Discovery",
    "T1087.001": "Local Account",
    "T1087.002": "Domain Account",
    "T1105": "Ingress Tool Transfer",
    "T1112": "Modify Registry",
    "T1127": "Trusted Developer Utilities Proxy Execution",
    "T1127.001": "MSBuild",
    "T1136": "Create Account",
    "T1136.001": "Local Account",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1190": "Exploit Public-Facing Application",
    "T1201": "Password Policy Discovery",
    "T1204": "User Execution",
    "T1204.002": "Malicious File",
    "T1218": "System Binary Proxy Execution",
    "T1218.001": "Compiled HTML File",
    "T1218.002": "Control Panel",
    "T1218.005": "Mshta",
    "T1218.010": "Regsvr32",
    "T1218.011": "Rundll32",
    "T1218.012": "Verclsid",
    "T1220": "XSL Script Processing",
    "T1222": "File and Directory Permissions Modification",
    "T1222.001": "Windows File and Directory Permissions Modification",
    "T1482": "Domain Trust Discovery",
    "T1485": "Data Destruction",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1505": "Server Software Component",
    "T1505.003": "Web Shell",
    "T1531": "Account Access Removal",
    "T1543": "Create or Modify System Process",
    "T1543.003": "Windows Service",
    "T1546": "Event Triggered Execution",
    "T1546.001": "Change Default File Association",
    "T1546.003": "Windows Management Instrumentation Event Subscription",
    "T1546.008": "Accessibility Features",
    "T1546.011": "Application Shimming",
    "T1546.012": "Image File Execution Options Injection",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1547.003": "Time Providers",
    "T1547.010": "Port Monitors",
    "T1547.012": "Print Processors",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1548.002": "Bypass User Account Control",
    "T1550": "Use Alternate Authentication Material",
    "T1550.002": "Pass the Hash",
    "T1550.003": "Pass the Ticket",
    "T1552": "Unsecured Credentials",
    "T1552.002": "Credentials in Registry",
    "T1553": "Subvert Trust Controls",
    "T1553.004": "Install Root Certificate",
    "T1555": "Credentials from Password Stores",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1558.003": "Kerberoasting",
    "T1560": "Archive Collected Data",
    "T1560.001": "Archive via Utility",
    "T1561": "Disk Wipe",
    "T1561.002": "Disk Structure Wipe",
    "T1562": "Impair Defenses",
    "T1562.001": "Disable or Modify Tools",
    "T1562.002": "Disable Windows Event Logging",
    "T1562.004": "Disable or Modify System Firewall",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1569": "System Services",
    "T1569.002": "Service Execution",
    "T1572": "Protocol Tunneling",
    "T1574": "Hijack Execution Flow",
    "T1574.001": "DLL Search Order Hijacking",
    "T1574.002": "DLL Side-Loading",
    "T1574.009": "Path Interception by Unquoted Path",
    "T1574.011": "Services Registry Permissions Weakness",
    "T1588": "Obtain Capabilities",
    "T1588.002": "Tool",
    "T1590": "Gather Victim Network Information",
    "T1590.002": "DNS",
    "T1595": "Active Scanning",
    "T1649": "Steal or Forge Authentication Certificates",
}


def technique_name(label: str) -> str:
    return ATTACK_NAMES.get(str(label), "Unknown ATT&CK technique name")


# ============================================================
# Load ML models
# ============================================================

print("[1/5] Loading ML models...")

parent_model = joblib.load(PARENT_MODEL_PATH)
sub_model = joblib.load(SUB_MODEL_PATH)


# ============================================================
# Text normalization
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
# ML prediction
# ============================================================

def topk(model, text: str, k: int = 5):
    proba = model.predict_proba([text])[0]
    classes = model.classes_

    idx = np.argsort(proba)[::-1][:k]

    return [
        {
            "label": str(classes[i]),
            "name": technique_name(str(classes[i])),
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

    if sub_conf >= SUBTECHNIQUE_THRESHOLD and get_parent(sub_label) == parent_label:
        final_label = sub_label
        final_level = "sub-technique"
        final_confidence = sub_conf
        decision_reason = (
            "Sub-technique prediction was accepted because its confidence passed "
            "the threshold and its parent matched the parent model."
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

    parent_label_final = get_parent(final_label)

    return {
        "final_label": final_label,
        "final_name": technique_name(final_label),
        "final_parent": parent_label_final,
        "final_parent_name": technique_name(parent_label_final),
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
        "summary": "LLM did not return valid JSON.",
        "attack_interpretation": raw,
        "technique_name": "Unknown",
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
- Include the human-readable MITRE ATT&CK technique name.
- Return ONLY valid JSON.
- Do not use markdown.

Return this JSON schema:

{{
  "summary": "...",
  "attack_interpretation": "...",
  "technique_id": "...",
  "technique_name": "...",
  "parent_technique_id": "...",
  "parent_technique_name": "...",
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

    # Safety fallback from ML mapping if LLM misses names
    parsed.setdefault("technique_id", ml_prediction.get("final_label"))
    parsed.setdefault("technique_name", ml_prediction.get("final_name"))
    parsed.setdefault("parent_technique_id", ml_prediction.get("final_parent"))
    parsed.setdefault("parent_technique_name", ml_prediction.get("final_parent_name"))

    return {
        "raw_llm_response": raw_response,
        "llm_explanation": parsed
    }


def analyze_event(event: dict):
    event_text = event_dict_to_text(event)
    ml_prediction = predict_hierarchical(event_text)
    llm_result = explain_with_llm(event_text, ml_prediction)

    return {
        "event_text": event_text,
        "ml_prediction": ml_prediction,
        "llm_explanation": llm_result["llm_explanation"],
        "raw_llm_response": llm_result["raw_llm_response"]
    }


if __name__ == "__main__":
    sample_event = {
        "EventID": "1",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgA...",
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "ParentCommandLine": "cmd.exe /c powershell.exe -enc SQBFAFgA...",
        "User": r"corp\alice",
        "Computer": "win10-01",
        "CurrentDirectory": r"C:\Users\alice\Downloads"
    }

    result = analyze_event(sample_event)

    Path("../reports").mkdir(exist_ok=True)
    with open("../reports/ml_plus_llm_explanation_example.json", "w") as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))
