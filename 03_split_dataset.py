from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split

RANDOM_STATE = 42

INPUT_FILE = "data/sysmon_events_text.csv"
OUTPUT_FILE = "data/sysmon_events_split.csv"

TEST_SIZE = 0.15
VAL_SIZE = 0.15

# Recommended for stable training
MIN_SAMPLES_PER_TECHNIQUE = 300

df = pd.read_csv(INPUT_FILE, dtype=str, low_memory=False).fillna("")

print("Original rows:", len(df))
print("Original techniques:", df["technique"].nunique())

# Keep only labels that can appear in train/val/test
counts = df["technique"].value_counts()
valid_labels = counts[counts >= MIN_SAMPLES_PER_TECHNIQUE].index
df = df[df["technique"].isin(valid_labels)].copy()

print("Filtered rows:", len(df))
print("Filtered techniques:", df["technique"].nunique())

# 1) Split test first
train_val_df, test_df = train_test_split(
    df,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=df["technique"]
)

# 2) Split validation from train_val
relative_val_size = VAL_SIZE / (1 - TEST_SIZE)

train_df, val_df = train_test_split(
    train_val_df,
    test_size=relative_val_size,
    random_state=RANDOM_STATE,
    stratify=train_val_df["technique"]
)

train_df = train_df.copy()
val_df = val_df.copy()
test_df = test_df.copy()

train_df["split"] = "train"
val_df["split"] = "val"
test_df["split"] = "test"

final_df = pd.concat([train_df, val_df, test_df], ignore_index=True)

Path("data").mkdir(exist_ok=True)
final_df.to_csv(OUTPUT_FILE, index=False)

print("\nFinal split:")
print(final_df["split"].value_counts())

print("\nTechnique count per split:")
print(final_df.groupby("split")["technique"].nunique())

# Safety check: every technique appears in all splits
split_labels = final_df.groupby("split")["technique"].apply(set)
common_labels = set.intersection(*split_labels)

all_labels = set(final_df["technique"].unique())
missing = all_labels - common_labels

if missing:
    print("\nWARNING: Some labels are missing from at least one split:")
    print(missing)
else:
    print("\nOK: Every technique appears in train, val, and test.")

print(f"\nSaved to {OUTPUT_FILE}")
