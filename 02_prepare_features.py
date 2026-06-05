import pandas as pd
from pathlib import Path
import re

IN = Path("data/sysmon_events_labeled.csv")
OUT = Path("data/sysmon_events_text.csv")

df = pd.read_csv(IN, dtype=str, low_memory=False).fillna("")

TEXT_FIELDS = [
    "EventID", "Image", "CommandLine", "ParentImage", "ParentCommandLine",
    "User", "Computer", "TargetFilename", "TargetObject", "Details",
    "DestinationIp", "DestinationPort", "QueryName", "CurrentDirectory"
]

def normalize(s: str) -> str:
    s = str(s).lower()
    s = re.sub(r"[a-z]:\\users\\[^\\\s]+", r"c:\\users\\<user>", s)
    s = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", "<ip>", s)
    s = re.sub(r"\b[0-9a-f]{32,64}\b", "<hash>", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()

def make_text(row):
    parts = []
    for f in TEXT_FIELDS:
        val = normalize(row.get(f, ""))
        if val:
            parts.append(f"{f}={val}")
    return " ".join(parts)

df["text"] = df.apply(make_text, axis=1)

# Keep classes with enough samples
min_samples = 20
counts = df["technique"].value_counts()
df = df[df["technique"].isin(counts[counts >= min_samples].index)]

df.to_csv(OUT, index=False)
print(df.shape)
print("Technique classes:", df["technique"].nunique())
print("Parent classes:", df["parent_technique"].nunique())
