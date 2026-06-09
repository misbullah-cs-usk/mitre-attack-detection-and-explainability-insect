from pathlib import Path
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, top_k_accuracy_score

DATA_FILE = "data/sysmon_sequences_window_size10_split.csv"

MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")
MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)


def build_model():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=70000,
            ngram_range=(1, 2),
            min_df=3,
            max_df=0.95,
            sublinear_tf=True
        )),
        ("clf", SGDClassifier(
            loss="modified_huber",
            class_weight="balanced",
            max_iter=60,
            tol=1e-4,
            n_jobs=-1,
            random_state=42,
            verbose=1
        ))
    ])


def evaluate(model, X, y, name):
    pred = model.predict(X)

    print(f"\n===== {name} =====")
    print(classification_report(y, pred, zero_division=0))

    proba = model.predict_proba(X)
    labels = model.classes_

    for k in [1, 3, 5]:
        if len(labels) >= k:
            score = top_k_accuracy_score(y, proba, k=k, labels=labels)
            print(f"{name} top-{k}: {score:.4f}")

    return pred


start = time.time()

print("[1/6] Loading data...")
df = pd.read_csv(DATA_FILE, dtype=str, low_memory=False).fillna("")

train_df = df[df["split"] == "train"]
val_df = df[df["split"] == "val"]
test_df = df[df["split"] == "test"]

print("Train:", len(train_df))
print("Val:", len(val_df))
print("Test:", len(test_df))
print("Techniques:", df["technique"].nunique())
print("Parents:", df["parent_technique"].nunique())

print("\n[2/6] Training parent sequence model...")
parent_model = build_model()
parent_model.fit(train_df["text"], train_df["parent_technique"])

print("\n[3/6] Evaluating parent sequence model...")
val_parent_pred = evaluate(parent_model, val_df["text"], val_df["parent_technique"], "Parent validation")
test_parent_pred = evaluate(parent_model, test_df["text"], test_df["parent_technique"], "Parent test")

joblib.dump(parent_model, MODEL_DIR / "tfidf_sgd_sequence_window_parent.joblib")

print("\n[4/6] Training sub-technique sequence model...")
sub_model = build_model()
sub_model.fit(train_df["text"], train_df["technique"])

print("\n[5/6] Evaluating sub-technique sequence model...")
val_sub_pred = evaluate(sub_model, val_df["text"], val_df["technique"], "Sub-technique validation")
test_sub_pred = evaluate(sub_model, test_df["text"], test_df["technique"], "Sub-technique test")

joblib.dump(sub_model, MODEL_DIR / "tfidf_sgd_sequence_window_subtechnique.joblib")

print("\n[6/6] Saving report...")
report = test_df.copy()
report["pred_parent"] = test_parent_pred
report["pred_technique"] = test_sub_pred
report["parent_correct"] = report["parent_technique"] == report["pred_parent"]
report["technique_correct"] = report["technique"] == report["pred_technique"]

report.to_csv(REPORT_DIR / "sequence_window_classical_ml_test_predictions.csv", index=False)

print("Saved models and report.")
print(f"Done in {(time.time() - start):.2f} seconds")
