from pathlib import Path
import pandas as pd

INPUT_FILE = "data/sysmon_events_split.csv"
OUTPUT_FILE = "data/sysmon_sequences_window_size10_split.csv"

WINDOW_SIZE = 10
STRIDE = 5
MIN_EVENTS_PER_SEQUENCE = 3

df = pd.read_csv(INPUT_FILE, dtype=str, low_memory=False).fillna("")

if "parent_technique" not in df.columns:
    df["parent_technique"] = df["technique"].apply(lambda x: x.split(".")[0])

if "UtcTime" in df.columns:
    df = df.sort_values(["split", "source_file", "UtcTime"])
else:
    df = df.sort_values(["split", "source_file"])

rows = []

for (split, source_file, technique), g in df.groupby(["split", "source_file", "technique"]):
    g = g.reset_index(drop=True)

    parent = technique.split(".")[0]
    events = g["text"].tolist()

    if len(events) < MIN_EVENTS_PER_SEQUENCE:
        continue

    for start in range(0, len(events), STRIDE):
        window = events[start:start + WINDOW_SIZE]

        if len(window) < MIN_EVENTS_PER_SEQUENCE:
            break

        rows.append({
            "split": split,
            "source_file": source_file,
            "technique": technique,
            "parent_technique": parent,
            "start_event": start,
            "end_event": start + len(window) - 1,
            "num_events": len(window),
            "text": " [EVENT] ".join(window)
        })

seq = pd.DataFrame(rows)

Path("data").mkdir(exist_ok=True)
seq.to_csv(OUTPUT_FILE, index=False)

print("Saved:", OUTPUT_FILE)
print("Rows:", len(seq))
print("Split counts:")
print(seq["split"].value_counts())
print("\nTechnique classes:", seq["technique"].nunique())
print("Parent classes:", seq["parent_technique"].nunique())
print("\nSequence length:")
print(seq["num_events"].describe())
print("\nTop techniques:")
print(seq["technique"].value_counts().head(20))
