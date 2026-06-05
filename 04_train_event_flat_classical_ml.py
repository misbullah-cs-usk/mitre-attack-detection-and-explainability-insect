from pathlib import Path
import pandas as pd
import joblib
import time

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report
import numpy as np
from sklearn.metrics import top_k_accuracy_score

start = time.time()

print("[1/5] Loading data...")
df = pd.read_csv(
    "data/sysmon_events_split.csv",
    dtype=str,
    low_memory=False
).fillna("")

train_df = df[df["split"] == "train"]
val_df = df[df["split"] == "val"]
test_df = df[df["split"] == "test"]

X_train = train_df["text"]
y_train = train_df["technique"]

X_val = val_df["text"]
y_val = val_df["technique"]

X_test = test_df["text"]
y_test = test_df["technique"]

## Optional: keep only classes with enough samples
#min_samples = 20
#counts = df["technique"].value_counts()
#df = df[df["technique"].isin(counts[counts >= min_samples].index)]
#
## Optional: sample for faster experiment
#MAX_ROWS = 30000
#if len(df) > MAX_ROWS:
#    print(f"[2/5] Sampling {MAX_ROWS} rows from {len(df)} rows...")
#    df = df.groupby("technique", group_keys=False).apply(
#        lambda x: x.sample(
#            min(len(x), max(5, MAX_ROWS // df["technique"].nunique())),
#            random_state=42
#        )
#    )
#else:
#    print("[2/5] Using full dataset...")
#
#print("Rows:", len(df))
#print("Classes:", df["technique"].nunique())
#
#print("[3/5] Splitting train/test...")
#X_train, X_test, y_train, y_test = train_test_split(
#    df["text"],
#    df["technique"],
#    test_size=0.2,
#    random_state=42,
#    stratify=df["technique"]
#)

print("[4/5] Training fast TF-IDF + SGD classifier...")
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        max_features=20000,      # was 80000
        ngram_range=(1, 2),      # was (1, 2)
        min_df=3,
        max_df=0.95,
        sublinear_tf=True
    )),
    ("clf", SGDClassifier(
        loss="log_loss",         # gives predict_proba
        class_weight="balanced",
        max_iter=300,
        tol=1e-3,
        n_jobs=-1,
        random_state=42,
        verbose=1
    ))
])

model.fit(X_train, y_train)

print("[5/5] Evaluating...")
pred = model.predict(X_test)

print(classification_report(y_test, pred, zero_division=0))

Path("models").mkdir(exist_ok=True)
joblib.dump(model, "models/tfidf_sgd_technique_fast.joblib")

print(f"Saved model to models/tfidf_sgd_technique_fast.joblib")
print(f"Done in {(time.time() - start):.2f} seconds")

proba = model.predict_proba(X_test)
classes = model.classes_

print("Top-1 accuracy:", model.score(X_test, y_test))
print("Top-3 accuracy:", top_k_accuracy_score(y_test, proba, k=3, labels=classes))
print("Top-5 accuracy:", top_k_accuracy_score(y_test, proba, k=5, labels=classes))

errors = test_df.copy()
errors["pred"] = pred
errors = errors[errors["technique"] != errors["pred"]]

errors[[
    "technique",
    "pred",
    "parent_technique",
    "EventID",
    "Image",
    "CommandLine",
    "ParentImage",
    "ParentCommandLine",
    "source_file"
]].to_csv("reports/classical_ml_errors.csv", index=False)
