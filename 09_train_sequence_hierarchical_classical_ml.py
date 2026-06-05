from pathlib import Path
import time
import joblib
import numpy as np
import pandas as pd

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import classification_report, top_k_accuracy_score


DATA_FILE = "data/sysmon_sequences_split.csv"

MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")
MODEL_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)


def build_model():
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            max_features=70000,
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.95,
            sublinear_tf=True
        )),
        ("clf", SGDClassifier(
            loss="modified_huber",
            class_weight="balanced",
            max_iter=5000,
            tol=1e-4,
            n_jobs=-1,
            random_state=42,
            verbose=0
        ))
    ])


def evaluate(model, X, y, name):
    pred = model.predict(X)

    print(f"\n===== {name} classification report =====")
    print(classification_report(y, pred, zero_division=0))

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)
        labels = model.classes_

        for k in [1, 3, 5]:
            if len(labels) >= k:
                score = top_k_accuracy_score(y, proba, k=k, labels=labels)
                print(f"{name} top-{k} accuracy: {score:.4f}")

    return pred


start = time.time()

print("[1/6] Loading sequence dataset...")
df = pd.read_csv(DATA_FILE, dtype=str, low_memory=False).fillna("")

train_df = df[df["split"] == "train"].copy()
val_df = df[df["split"] == "val"].copy()
test_df = df[df["split"] == "test"].copy()

print("Train sequences:", len(train_df))
print("Val sequences:", len(val_df))
print("Test sequences:", len(test_df))
print("Technique classes:", df["technique"].nunique())
print("Parent classes:", df["parent_technique"].nunique())


# -------------------------
# Parent sequence model
# -------------------------
print("\n[2/6] Training sequence parent-technique model...")
parent_model = build_model()

parent_model.fit(
    train_df["text"],
    train_df["parent_technique"]
)

print("\n[3/6] Evaluating sequence parent-technique model...")
val_parent_pred = evaluate(
    parent_model,
    val_df["text"],
    val_df["parent_technique"],
    "Sequence parent validation"
)

test_parent_pred = evaluate(
    parent_model,
    test_df["text"],
    test_df["parent_technique"],
    "Sequence parent test"
)

joblib.dump(parent_model, MODEL_DIR / "tfidf_sgd_sequence_parent.joblib")


# -------------------------
# Sub-technique sequence model
# -------------------------
print("\n[4/6] Training sequence sub-technique model...")
sub_model = build_model()

sub_model.fit(
    train_df["text"],
    train_df["technique"]
)

print("\n[5/6] Evaluating sequence sub-technique model...")
val_sub_pred = evaluate(
    sub_model,
    val_df["text"],
    val_df["technique"],
    "Sequence sub-technique validation"
)

test_sub_pred = evaluate(
    sub_model,
    test_df["text"],
    test_df["technique"],
    "Sequence sub-technique test"
)

joblib.dump(sub_model, MODEL_DIR / "tfidf_sgd_sequence_subtechnique.joblib")


print("\n[6/6] Saving sequence prediction report...")

report = test_df.copy()
report["pred_parent"] = test_parent_pred
report["pred_technique"] = test_sub_pred
report["parent_correct"] = report["parent_technique"] == report["pred_parent"]
report["technique_correct"] = report["technique"] == report["pred_technique"]

report.to_csv(
    REPORT_DIR / "sequence_classical_ml_test_predictions.csv",
    index=False
)

print("Saved:")
print("models/tfidf_sgd_sequence_parent.joblib")
print("models/tfidf_sgd_sequence_subtechnique.joblib")
print("reports/sequence_classical_ml_test_predictions.csv")

print(f"\nDone in {(time.time() - start):.2f} seconds")
