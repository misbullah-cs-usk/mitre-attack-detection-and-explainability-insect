from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd
import torch

from datasets import Dataset
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, classification_report, top_k_accuracy_score
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    TrainingArguments,
    Trainer,
    DataCollatorWithPadding,
    EarlyStoppingCallback
)

# =========================
# Config
# =========================

DATA_FILE = "data/sysmon_sequences_split.csv"
#MODEL_NAME = "distilbert-base-uncased"
MODEL_NAME = "microsoft/MiniLM-L12-H384-uncased"

OUTPUT_DIR = Path("models/sequence_transformer_subtechnique")
REPORT_DIR = Path("reports")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

TARGET_COLUMN = "technique"   # use "parent_technique" for parent model
TEXT_COLUMN = "text"

MAX_LENGTH = 512
NUM_EPOCHS = 8
BATCH_SIZE = 8
LEARNING_RATE = 2e-5

RANDOM_STATE = 42


def compute_topk(logits, labels, k):
    if logits.shape[1] < k:
        return None
    return top_k_accuracy_score(
        labels,
        logits,
        k=k,
        labels=list(range(logits.shape[1]))
    )


def main():
    print("[1/8] Loading sequence data...")
    df = pd.read_csv(DATA_FILE, dtype=str, low_memory=False).fillna("")

    if "parent_technique" not in df.columns:
        df["parent_technique"] = df["technique"].apply(lambda x: x.split(".")[0])

    train_df = df[df["split"] == "train"].copy()
    val_df = df[df["split"] == "val"].copy()
    test_df = df[df["split"] == "test"].copy()

    print("Train sequences:", len(train_df))
    print("Val sequences:", len(val_df))
    print("Test sequences:", len(test_df))
    print("Classes:", df[TARGET_COLUMN].nunique())

    print("[2/8] Encoding labels...")
    label_encoder = LabelEncoder()
    label_encoder.fit(df[TARGET_COLUMN])

    train_df["label"] = label_encoder.transform(train_df[TARGET_COLUMN])
    val_df["label"] = label_encoder.transform(val_df[TARGET_COLUMN])
    test_df["label"] = label_encoder.transform(test_df[TARGET_COLUMN])

    id2label = {i: label for i, label in enumerate(label_encoder.classes_)}
    label2id = {label: i for i, label in id2label.items()}

    joblib.dump(label_encoder, OUTPUT_DIR / "label_encoder.joblib")

    with open(OUTPUT_DIR / "label_mapping.json", "w") as f:
        json.dump({"id2label": id2label, "label2id": label2id}, f, indent=2)

    print("[3/8] Creating Hugging Face datasets...")
    train_ds = Dataset.from_pandas(train_df[[TEXT_COLUMN, "label"]], preserve_index=False)
    val_ds = Dataset.from_pandas(val_df[[TEXT_COLUMN, "label"]], preserve_index=False)
    test_ds = Dataset.from_pandas(test_df[[TEXT_COLUMN, "label"]], preserve_index=False)

    print("[4/8] Tokenizing sequences...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    def tokenize(batch):
        return tokenizer(
            batch[TEXT_COLUMN],
            truncation=True,
            max_length=MAX_LENGTH
        )

    train_ds = train_ds.map(tokenize, batched=True)
    val_ds = val_ds.map(tokenize, batched=True)
    test_ds = test_ds.map(tokenize, batched=True)

    data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

    print("[5/8] Loading Transformer model...")
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME,
        num_labels=len(label_encoder.classes_),
        id2label=id2label,
        label2id=label2id
    )

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)

        metrics = {
            "accuracy": accuracy_score(labels, preds),
            "macro_f1": f1_score(labels, preds, average="macro", zero_division=0),
            "weighted_f1": f1_score(labels, preds, average="weighted", zero_division=0)
        }

        for k in [3, 5]:
            score = compute_topk(logits, labels, k)
            if score is not None:
                metrics[f"top_{k}_accuracy"] = score

        return metrics

    print("[6/8] Setting training arguments...")
    args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        evaluation_strategy="epoch",
        save_strategy="epoch",
        logging_strategy="steps",
        logging_steps=10,
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=BATCH_SIZE,
        per_device_eval_batch_size=BATCH_SIZE,
        num_train_epochs=NUM_EPOCHS,
        weight_decay=0.01,
        load_best_model_at_end=True,
        metric_for_best_model="macro_f1",
        greater_is_better=True,
        save_total_limit=2,
        report_to="none",
        fp16=torch.cuda.is_available()
    )

    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
    )

    print("[7/8] Training sequence Transformer...")
    trainer.train()

    print("[8/8] Final test evaluation...")
    test_output = trainer.predict(test_ds)
    logits = test_output.predictions
    y_true = test_output.label_ids
    y_pred = np.argmax(logits, axis=-1)

    print(test_output.metrics)

    report_text = classification_report(
        y_true,
        y_pred,
        target_names=label_encoder.classes_,
        zero_division=0
    )

    print(report_text)

    with open(REPORT_DIR / "sequence_transformer_subtechnique_report.txt", "w") as f:
        f.write(report_text)
        f.write("\n\n")
        f.write(json.dumps(test_output.metrics, indent=2))

    pred_df = test_df.copy()
    pred_df["pred_label"] = label_encoder.inverse_transform(y_pred)
    pred_df["correct"] = pred_df[TARGET_COLUMN] == pred_df["pred_label"]

    pred_df.to_csv(REPORT_DIR / "sequence_transformer_subtechnique_predictions.csv", index=False)

    trainer.save_model(str(OUTPUT_DIR / "best_model"))
    tokenizer.save_pretrained(str(OUTPUT_DIR / "best_model"))

    print("Saved model:", OUTPUT_DIR / "best_model")
    print("Saved report:", REPORT_DIR / "sequence_transformer_subtechnique_report.txt")


if __name__ == "__main__":
    main()
