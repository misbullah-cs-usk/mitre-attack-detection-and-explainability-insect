from pathlib import Path
import re
import xml.etree.ElementTree as ET
import pandas as pd
from tqdm import tqdm

ATTACK_DATA_DIR = Path("/home/alim/PhD-Experiments/Alim/CyberSecurity/data/raw/attack_data/datasets/attack_techniques")
OUT = Path("data")
OUT.mkdir(exist_ok=True)

FIELDS = [
    "UtcTime", "EventID", "Image", "CommandLine", "ParentImage",
    "ParentCommandLine", "User", "Computer", "TargetFilename",
    "TargetObject", "Details", "DestinationIp", "DestinationPort",
    "SourceIp", "SourcePort", "QueryName", "Hashes", "CurrentDirectory"
]

def parent_technique(tid: str) -> str:
    return tid.split(".")[0]

def parse_sysmon_event(xml_text: str) -> dict:
    row = {f: "" for f in FIELDS}

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return row

    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    event_id = root.findtext(".//e:System/e:EventID", default="", namespaces=ns)
    computer = root.findtext(".//e:System/e:Computer", default="", namespaces=ns)
    row["EventID"] = event_id
    row["Computer"] = computer

    for data in root.findall(".//e:EventData/e:Data", ns):
        name = data.attrib.get("Name", "")
        if name in row:
            row[name] = data.text or ""

    return row

def split_events(raw: str):
    # Splunk attack_data sysmon logs are usually XML events one after another.
    events = re.findall(r"<Event xmlns=.*?</Event>", raw, flags=re.DOTALL)
    return events

rows = []

for technique_dir in tqdm(list(ATTACK_DATA_DIR.glob("T*"))):
    technique = technique_dir.name
    if not re.match(r"^T\d{4}(\.\d{3})?$", technique):
        continue

    for log_file in technique_dir.rglob("*sysmon*.log"):
        try:
            raw = log_file.read_text(errors="ignore")
        except Exception:
            continue

        events = split_events(raw)
        for ev in events:
            row = parse_sysmon_event(ev)
            row["technique"] = technique
            row["parent_technique"] = parent_technique(technique)
            row["source_file"] = str(log_file)
            rows.append(row)

df = pd.DataFrame(rows)

# Remove empty/weak rows
df = df.fillna("")
df = df[df["EventID"].astype(str).str.len() > 0]

df.to_csv(OUT / "sysmon_events_labeled.csv", index=False)

print(df.shape)
print(df[["technique", "parent_technique"]].drop_duplicates().head())
print(df["technique"].value_counts().head(20))
