from pathlib import Path
import pandas as pd

INPUT_FILE = "data/sysmon_events_split.csv"
OUTPUT_FILE = "data/sysmon_sequences_split.csv"

MAX_EVENTS_PER_SEQUENCE = 20

df = pd.read_csv(INPUT_FILE, dtype=str, low_memory=False).fillna("")

# Sort events temporally if time exists
if "UtcTime" in df.columns:
    df = df.sort_values(["split", "source_file", "UtcTime"])
else:
    df = df.sort_values(["split", "source_file"])

sequence_rows = []

for (split, source_file, technique), g in df.groupby(["split", "source_file", "technique"]):
    g = g.head(MAX_EVENTS_PER_SEQUENCE)

    parent_technique = technique.split(".")[0]

    event_texts = g["text"].tolist()

    sequence_text = " [EVENT] ".join(event_texts)

    sequence_rows.append({
        "split": split,
        "source_file": source_file,
        "technique": technique,
        "parent_technique": parent_technique,
        "num_events": len(g),
        "text": sequence_text
    })

seq_df = pd.DataFrame(sequence_rows)

Path("data").mkdir(exist_ok=True)
seq_df.to_csv(OUTPUT_FILE, index=False)

print("Saved:", OUTPUT_FILE)
print("Rows:", len(seq_df))
print("Technique classes:", seq_df["technique"].nunique())
print("Parent classes:", seq_df["parent_technique"].nunique())
print(seq_df["split"].value_counts())
print(seq_df["num_events"].describe())
