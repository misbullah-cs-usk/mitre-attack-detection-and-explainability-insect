import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:7b-instruct"

log_text = """
EventID=1
Image=c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe
CommandLine=powershell.exe -nop -w hidden -enc SQBFAFgA...
ParentImage=c:\\windows\\system32\\cmd.exe
ParentCommandLine=cmd.exe /c powershell.exe -enc SQBFAFgA...
User=corp\\alice
Computer=win10-01
"""

prompt = f"""
You are a SOC analyst.

Analyze the Windows/Sysmon log below.

Tasks:
1. Decide whether the activity is benign, suspicious, or malicious.
2. Predict the most likely MITRE ATT&CK parent technique.
3. Predict the most likely MITRE ATT&CK sub-technique if possible.
4. Explain the reason clearly.
5. Give triage steps.

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

response = requests.post(OLLAMA_URL, json=payload, timeout=120)
response.raise_for_status()

raw = response.json()["response"]

print(raw)

try:
    parsed = json.loads(raw)
    print("\nParsed JSON:")
    print(json.dumps(parsed, indent=2))
except Exception:
    print("\nWARNING: Model did not return valid JSON.")
